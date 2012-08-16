({

  appDir: "../",
  baseUrl: "assets/js/app",
  dir: "../../surespot-built",
  modules: [
    {
      name: "main"
    }
  ],
  mainConfigFile: '../assets/js/app/main.js',
  paths: {
    'socket.io': '../../../node_modules/socket.io/node_modules/socket.io-client/dist/socket.io'
  }
})