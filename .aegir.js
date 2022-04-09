
/** @type {import('aegir/types').PartialOptions} */
export default {
  test: {
    browser: {
      config: {
        entryPoints: ['./dist/src/index.js']
      }
    }
  },
  build: {
    config: {
      entryPoints: ['./dist/src/index.js']
    }
  }
}
