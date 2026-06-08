// Facade for subscribing to domain events without importing other domains directly.
// Domains and engines should depend on `runtime::events` rather than importing other domains.
use std::any::TypeId;

pub struct Subscription {
    pub id: usize,
    pub type_id: TypeId,
}

impl Subscription {
    fn new(id: usize, type_id: TypeId) -> Self {
        Self { id, type_id }
    }
}

impl Drop for Subscription {
    fn drop(&mut self) {
        crate::runtime::event_bus::unsubscribe_by_typeid(self.type_id, self.id);
    }
}

pub fn subscribe_to_process_events(h: Box<dyn Fn(&crate::domains::process::events::ProcessEvent) + Send + Sync + 'static>) -> Subscription {
    let id = crate::runtime::event_bus::subscribe::<crate::domains::process::events::ProcessEvent>(h);
    Subscription::new(id, TypeId::of::<crate::domains::process::events::ProcessEvent>())
}

pub fn unsubscribe_from_process_events(id: usize) {
    crate::runtime::event_bus::unsubscribe::<crate::domains::process::events::ProcessEvent>(id);
}

pub fn subscribe_to_cpu_events(h: Box<dyn Fn(&crate::domains::cpu::events::CpuEvent) + Send + Sync + 'static>) -> Subscription {
    let id = crate::runtime::event_bus::subscribe::<crate::domains::cpu::events::CpuEvent>(h);
    Subscription::new(id, TypeId::of::<crate::domains::cpu::events::CpuEvent>())
}

pub fn unsubscribe_from_cpu_events(id: usize) {
    crate::runtime::event_bus::unsubscribe::<crate::domains::cpu::events::CpuEvent>(id);
}

pub fn subscribe_to_memory_events(h: Box<dyn Fn(&crate::domains::memory::events::MemoryEvent) + Send + Sync + 'static>) -> Subscription {
    let id = crate::runtime::event_bus::subscribe::<crate::domains::memory::events::MemoryEvent>(h);
    Subscription::new(id, TypeId::of::<crate::domains::memory::events::MemoryEvent>())
}

pub fn unsubscribe_from_memory_events(id: usize) {
    crate::runtime::event_bus::unsubscribe::<crate::domains::memory::events::MemoryEvent>(id);
}

pub fn subscribe_to_security_events(h: Box<dyn Fn(&crate::domains::security::events::SecurityEvent) + Send + Sync + 'static>) -> Subscription {
    let id = crate::runtime::event_bus::subscribe::<crate::domains::security::events::SecurityEvent>(h);
    Subscription::new(id, TypeId::of::<crate::domains::security::events::SecurityEvent>())
}

pub fn unsubscribe_from_security_events(id: usize) {
    crate::runtime::event_bus::unsubscribe::<crate::domains::security::events::SecurityEvent>(id);
}

pub fn subscribe_to_rules_findings(h: Box<dyn Fn(&crate::domains::rules::Finding) + Send + Sync + 'static>) -> Subscription {
    let id = crate::runtime::event_bus::subscribe::<crate::domains::rules::Finding>(h);
    Subscription::new(id, TypeId::of::<crate::domains::rules::Finding>())
}

pub fn unsubscribe_from_rules_findings(id: usize) {
    crate::runtime::event_bus::unsubscribe::<crate::domains::rules::Finding>(id);
}

// Simple UI message type that surfaces can subscribe to for displaying
// outputs from REPL commands like `why` or `show graph`.
#[derive(Debug, Clone)]
pub struct UiMessage {
    pub topic: String,
    pub body: String,
}

pub fn subscribe_to_ui_messages(h: Box<dyn Fn(&UiMessage) + Send + Sync + 'static>) -> Subscription {
    let id = crate::runtime::event_bus::subscribe::<UiMessage>(h);
    Subscription::new(id, TypeId::of::<UiMessage>())
}

pub fn unsubscribe_from_ui_messages(id: usize) {
    crate::runtime::event_bus::unsubscribe::<UiMessage>(id);
}
