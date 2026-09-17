import { createRouter, createWebHistory } from 'vue-router'

import HomeView from '@/views/HomeView.vue'
import WriteView from '@/views/WriteView.vue'
import UploadView from '@/views/UploadView.vue'
import FilesView from '@/views/FilesView.vue'
import ArchiveView from '@/views/ArchiveView.vue'
import ReviewView from '@/views/ReviewView.vue'
import AboutView from '@/views/AboutView.vue'
import DetailView from '@/views/DetailView.vue'
import NotFoundView from '@/views/NotFoundView.vue'

import LoginView from '@/views/LoginView.vue'
import RegisterView from '@/views/RegisterView.vue'
import ShopView from '@/views/ShopView.vue'
import CartView from '@/views/CartView.vue'
import AdminView from '@/views/AdminView.vue'
import AuditView from '@/views/AuditView.vue'
import MerchantView from '@/views/MerchantView.vue'
import ForbiddenView from '@/views/ForbiddenView.vue'

import { state } from '@/stores/auth'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', name: 'home', component: HomeView },
    { path: '/write', name: 'write', component: WriteView },
    { path: '/upload', name: 'upload', component: UploadView },
    { path: '/files', name: 'files', component: FilesView },
    { path: '/archive', name: 'archive', component: ArchiveView },
    { path: '/review', name: 'review', component: ReviewView },
    { path: '/about', name: 'about', component: AboutView },
    { path: '/post/:id', name: 'post-detail', component: DetailView, props: { contentType: 'article' } },
    { path: '/file/:id', name: 'file-detail', component: DetailView, props: { contentType: 'file' } },

    // 认证
    { path: '/login', name: 'login', component: LoginView },
    { path: '/register', name: 'register', component: RegisterView },

    // 商城（普通用户/商户）
    { path: '/shop', name: 'shop', component: ShopView, meta: { requiresAuth: true } },
    { path: '/cart', name: 'cart', component: CartView, meta: { requiresAuth: true } },

    // 管理员后台
    { path: '/admin', name: 'admin', component: AdminView, meta: { requiresAuth: true, roles: ['admin'] } },
    // 商户后台
    { path: '/merchant', name: 'merchant', component: MerchantView, meta: { requiresAuth: true, roles: ['merchant'] } },
    // 审计日志
    { path: '/audit', name: 'audit', component: AuditView, meta: { requiresAuth: true, roles: ['auditor'] } },

    // 无权限（403）
    { path: '/403', name: 'forbidden', component: ForbiddenView },

    { path: '/:pathMatch(.*)*', name: 'not-found', component: NotFoundView }
  ],
  scrollBehavior() {
    return { top: 0 }
  }
})

// 路由守卫：登录校验 + 角色校验
router.beforeEach((to) => {
  const token = state.token
  const userRole = state.user?.role

  if (to.meta.requiresAuth && !token) {
    return { name: 'login', query: { redirect: to.fullPath } }
  }

  if (to.meta.roles && Array.isArray(to.meta.roles)) {
    if (!to.meta.roles.includes(userRole)) {
      // 无权限：返回 403
      return { name: 'forbidden' }
    }
  }

  return true
})

export default router