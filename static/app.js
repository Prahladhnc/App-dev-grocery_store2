new Vue({
  el: '#app',
  data: {
    product: productData,
    quantity: 1,
    totalCost: 0,
  },
  methods: {
    updateTotalCost() {
      this.totalCost = this.quantity * this.product.rate;
    },
  },
  watch: {
    quantity: 'updateTotalCost',
  },
});
