import { createApp } from 'vue'
import App from './App.vue'
import router from './router'
// 全局纵向布局（置于路由之后加载，确保最后注入）
import './styles/layout.css'

createApp(App).use(router).mount('#app')
