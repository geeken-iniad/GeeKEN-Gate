export const allowingRateLimiter: RateLimit = {
  async limit() {
    return { success: true }
  },
}
