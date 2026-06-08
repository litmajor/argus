use once_cell::sync::Lazy;
use std::any::{Any, TypeId};
use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

type Handler = dyn Fn(&dyn Any) + Send + Sync + 'static;

static SUBSCRIBERS: Lazy<Mutex<HashMap<TypeId, Vec<(usize, Arc<Handler>)>>>> = Lazy::new(|| Mutex::new(HashMap::new()));
static NEXT_ID: AtomicUsize = AtomicUsize::new(1);

/// Subscribe to events of type `T`. Returns a subscription id which can be used to unsubscribe.
pub fn subscribe<T: 'static + Send + Sync>(h: Box<dyn Fn(&T) + Send + Sync + 'static>) -> usize {
    let id = NEXT_ID.fetch_add(1, Ordering::SeqCst);
    let type_id = TypeId::of::<T>();
    let wrapper: Arc<Handler> = Arc::new(move |a: &dyn Any| {
        if let Some(v) = a.downcast_ref::<T>() {
            h(v);
        }
    });

    let mut map = SUBSCRIBERS.lock().unwrap();
    map.entry(type_id).or_default().push((id, wrapper));
    id
}

/// Unsubscribe a previously registered handler for type `T` by id.
pub fn unsubscribe<T: 'static>(id: usize) {
    let type_id = TypeId::of::<T>();
    let mut map = SUBSCRIBERS.lock().unwrap();
    if let Some(vec) = map.get_mut(&type_id) {
        vec.retain(|(sid, _)| *sid != id);
        if vec.is_empty() {
            map.remove(&type_id);
        }
    }
}

/// Unsubscribe by TypeId (runtime helper for non-generic callers)
pub fn unsubscribe_by_typeid(type_id: TypeId, id: usize) {
    let mut map = SUBSCRIBERS.lock().unwrap();
    if let Some(vec) = map.get_mut(&type_id) {
        vec.retain(|(sid, _)| *sid != id);
        if vec.is_empty() {
            map.remove(&type_id);
        }
    }
}

/// Publish an event of type `T` to all subscribers of that type.
pub fn publish<T: 'static + Send + Sync>(evt: T) {
    let type_id = TypeId::of::<T>();
    // Clone the handlers (Arc clones are cheap) while holding the lock,
    // then drop the lock and invoke handlers to avoid deadlocks when
    // handlers publish new events.
    let handlers: Vec<Arc<Handler>> = {
        let map = SUBSCRIBERS.lock().unwrap();
        if let Some(vec) = map.get(&type_id) {
            vec.iter().map(|(_id, h)| h.clone()).collect()
        } else {
            Vec::new()
        }
    };

    for handler in handlers {
        handler(&evt as &dyn Any);
    }
}
