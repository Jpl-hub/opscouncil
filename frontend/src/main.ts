import { createApp } from 'vue'
import { createPinia } from 'pinia'
import {
  Button,
  Drawer,
  Input,
  Modal,
  Pagination,
  Popconfirm,
  Select,
  Tag,
  Textarea,
} from '@arco-design/web-vue'
import '@arco-design/web-vue/es/button/style/css.js'
import '@arco-design/web-vue/es/drawer/style/css.js'
import '@arco-design/web-vue/es/input/style/css.js'
import '@arco-design/web-vue/es/modal/style/css.js'
import '@arco-design/web-vue/es/pagination/style/css.js'
import '@arco-design/web-vue/es/popconfirm/style/css.js'
import '@arco-design/web-vue/es/select/style/css.js'
import '@arco-design/web-vue/es/tag/style/css.js'
import '@arco-design/web-vue/es/textarea/style/css.js'
import './style.css'
import App from './App.vue'

const app = createApp(App)

app.use(createPinia())
app.use(Button)
app.use(Drawer)
app.use(Input)
app.use(Modal)
app.use(Pagination)
app.use(Popconfirm)
app.use(Select)
app.use(Tag)
app.use(Textarea)
app.mount('#app')
