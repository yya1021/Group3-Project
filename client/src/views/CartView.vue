<template>
  <main class="cart-page" style="max-width: 760px; margin: 2rem auto; padding: 2rem 1rem; flex: 1;">
    <h2 class="cart-title">购物车</h2>

    <div v-if="cart.length === 0" class="empty">购物车为空，去<a @click.prevent="$router.push('/shop')">商城</a>逛逛吧</div>

    <ul v-else class="cart-items">
      <li v-for="item in cart" :key="item.id" class="cart-item">
        <div class="item-image"><img :src="item.photo" :alt="item.name"></div>
        <div class="item-info">
          <h3>{{ item.name }}</h3>
          <p class="item-price">¥{{ item.price }}</p>
        </div>
        <div class="item-actions">
          <button class="btn-qty" @click="decrease(item)">-</button>
          <span class="qty">{{ item.amount }}</span>
          <button class="btn-qty" @click="increase(item)">+</button>
        </div>
      </li>
    </ul>

    <div v-if="cart.length > 0" class="cart-footer">
      <div class="total">总计：<span class="total-price">¥{{ totalPrice }}</span></div>
      <button class="btn-pay" :disabled="paying" @click="pay">{{ paying ? '支付中...' : '立即支付' }}</button>
    </div>

    <h2 v-if="orders.length > 0" class="orders-title">我的订单</h2>
    <ul v-if="orders.length > 0" class="order-list">
      <li v-for="o in orders" :key="o.id" class="order-item">
        <div class="order-main">
          <p class="order-no">订单号：{{ o.orderNumber }}</p>
          <p class="order-products">{{ o.products.map(p => `${p.name}×${p.amount}`).join('、') }}</p>
        </div>
        <div class="order-side">
          <div class="order-amount">¥{{ o.totalAmount }}</div>
          <button class="btn-cancel" @click="cancelOrder(o)">取消订单</button>
        </div>
      </li>
    </ul>
  </main>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { api } from '@/api'

const cart = ref([])
const orders = ref([])
const paying = ref(false)

const totalPrice = computed(() => cart.value.reduce((sum, i) => sum + i.price * (i.amount || 1), 0))

async function loadCart() {
  try {
    const data = await api.getCart()
    cart.value = data.cart || []
  } catch (e) { cart.value = [] }
}

async function loadOrders() {
  try {
    const data = await api.getOrders()
    orders.value = data.orders || []
  } catch (e) { orders.value = [] }
}

function decrease(item) {
  item.amount--
  if (item.amount <= 0) cart.value = cart.value.filter(i => i.id !== item.id)
  saveCart()
}

function increase(item) {
  item.amount = (item.amount || 0) + 1
  saveCart()
}

async function saveCart() {
  try { await api.saveCart(cart.value.map(i => ({ id: i.id, amount: i.amount || 1 }))) } catch (e) {}
}

async function cancelOrder(o) {
  if (!confirm('确定取消该订单？取消后将恢复商品库存。')) return
  try {
    await api.deleteOrder(o.id)
    alert('订单已取消')
    await loadOrders()
  } catch (e) {
    alert(e.message || '取消失败')
  }
}

async function pay() {
  paying.value = true
  try {
    const result = await api.createOrder(cart.value.map(i => ({ id: i.id, amount: i.amount || 1 })))
    if (result.success) {
      alert(`支付成功，订单金额 ¥${result.totalAmount}`)
      cart.value = []
      await api.saveCart([])
      await loadOrders()
    } else {
      alert(result.message || '下单失败')
    }
  } catch (e) {
    alert(e.message || '下单失败')
  } finally {
    paying.value = false
  }
}

onMounted(() => {
  loadCart()
  loadOrders()
})
</script>

<style scoped>
.cart-title { margin: 0 0 1.5rem; }
.empty { padding: 3rem; text-align: center; color: #666; }
.empty a { color: #457b9d; cursor: pointer; }
.cart-items { list-style: none; padding: 0; margin: 0; }
.cart-item { display: flex; align-items: center; padding: 1rem; background: #fff; border-bottom: 1px solid #eee; border-radius: 6px; margin-bottom: .5rem; }
.item-image img { width: 4rem; height: 4rem; object-fit: cover; border-radius: 4px; }
.item-info { flex: 1; margin: 0 1rem; }
.item-info h3 { margin: 0 0 .3rem; font-size: 1rem; }
.item-price { margin: 0; color: #e63946; font-weight: bold; }
.item-actions { display: flex; align-items: center; gap: .5rem; }
.btn-qty { width: 2rem; height: 2rem; border: 1px solid #ccc; background: #fff; border-radius: 4px; cursor: pointer; }
.qty { min-width: 1.5rem; text-align: center; }
.cart-footer { display: flex; justify-content: space-between; align-items: center; padding: 1rem; background: #f8f8f8; border-radius: 6px; margin-top: 1rem; }
.total { font-size: 1.1rem; font-weight: bold; }
.total-price { color: #e63946; }
.btn-pay { background: #28a745; color: #fff; border: none; border-radius: 4px; padding: .7rem 2rem; cursor: pointer; font-size: 1rem; }
.btn-pay:disabled { opacity: .6; cursor: not-allowed; }
.orders-title { margin: 2rem 0 1rem; }
.order-list { list-style: none; padding: 0; }
.order-item { display: flex; justify-content: space-between; align-items: center; padding: 1rem; background: #fff; border-radius: 6px; margin-bottom: .5rem; gap: 1rem; }
.order-main { flex: 1; }
.order-side { display: flex; flex-direction: column; align-items: flex-end; gap: .5rem; }
.order-no { margin: 0 0 .3rem; color: #333; font-size: .9rem; }
.order-products { margin: 0; color: #666; font-size: .85rem; }
.order-amount { color: #e63946; font-weight: bold; }
.btn-cancel { background: #e63946; color: #fff; border: none; border-radius: 4px; padding: .4rem .8rem; cursor: pointer; font-size: .85rem; }
</style>