
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
    bundlesizeMax: '66kB',
    config: {
      entryPoints: ['./dist/src/index.js']
    }
  }
}
