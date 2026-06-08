import { useArgusBridge } from './hooks/useArgusBridge'
import { DefaultWorkspace } from './workspace/DefaultWorkspace'

export default function App() {
  useArgusBridge()
  return <DefaultWorkspace />
}
