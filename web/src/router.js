import { createRouter, createWebHistory } from 'vue-router'

export const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', name: 'landing', component: () => import('./views/Landing.vue') },
    { path: '/signets', name: 'signets', component: () => import('./views/Signets.vue') },
    { path: '/signets/:id', name: 'approve', component: () => import('./views/Approve.vue') },
    { path: '/pair', name: 'pair', component: () => import('./views/Pair.vue') },
    { path: '/:pathMatch(.*)*', redirect: '/' },
  ],
  scrollBehavior: () => ({ top: 0 }),
})
