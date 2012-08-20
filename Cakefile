{print} = require 'sys'
{spawn} = require 'child_process'
fse = require 'fs-extra'


ccc = commonCoffeeCordova = (callback) ->
  exec 'coffee', ['-c', '-o', 'android/assets/js/app/', 'common/src/client/'], callback


ccn = commonCoffeeNode = (callback) ->
  exec 'coffee', ['-c', '-o', 'node/assets/js/app/', 'common/src/client/'], callback

copyCommonCssNode = (callback) ->
  fse.mkdir 'node/assets/css', ->
    fse.copy('common/css', 'node/assets/css', callback)

copyCommonCssCordova = (callback) ->
  fse.mkdir 'android/assets/css', ->
    fse.copy('common/css', 'android/assets/css/', callback)

copyCommonLibCordova = (callback) ->
  fse.mkdir 'android/assets/js/lib', ->
    fse.copy('common/lib', 'android/assets/js/lib/', callback)

copyCommonLibNode = (callback) ->
  fse.mkdir 'node/assets/js/lib', ->
    fse.copy('common/lib', 'node/assets/js/lib/', callback)

cc = coffeeCordova = (callback) ->
  exec 'coffee', ['-c', '-o', 'android/assets/js/app/', 'android/websrc'], callback

task 'cn', 'compile src coffee to node assets', ->
  coffeeNode()

task 'cc', 'compile src coffee to cordova assets', ->
  coffeeCordova()

task 'bc', 'build all cordova assets', ->
  commonCoffeeCordova(coffeeCordova)
  copyCommonCssCordova((err) -> console.log err if err?)
  copyCommonLibCordova((err) -> console.log err if err?)
  jadeCordova()


task 'bn', 'build all node assets', ->
  commonCoffeeNode(
    jadeNode(
      copyCommonCssNode((err) ->
        return console.log err if err?
        copyCommonLibNode((err) -> console.log err if err?))))


task 'ccssn', 'copy common css to node', ->
  copyCommonCssNode((err) -> console.log err if err?)

task 'cccc', 'copy common css to cordova', ->
  copyCommonCssCordova((err) -> console.log err if err?)

task 'ccln', 'copy common lib to node', ->
  copyCommonLibNode((err) -> console.log err if err?)

task 'cclc', 'copy common lib to cordova', ->
  copyCommonLibCordova((err) -> console.log err if err?)

task 'wcn', 'Watch src/ for coffee changes, update node', ->
  exec 'coffee', ['-w', '-c', '-o', 'node/assets/js/app/', 'common/src/client']

optimizeNode = (callback) ->
  exec 'node', ['build/r.js', '-o', 'build/node.build.js']

task 'optimize', 'r.js the code', ->
  optimize()


jadeNode = (callback) ->
  exec "jade", ['common/src/views/layout.jade', '--out', 'node/assets/html/'], callback


task "jn", "compile 'jade'files to node '.html'", (options) ->
  jadeNode()


task "jap", "compile jade templates to android html folder", (options) ->
  jadeCordova()

jadeCordova = (callback) ->
  exec "jade", ['common/src/views/layout.jade', '-P', '--out', 'android/assets/html/'], callback

exec = (command, args, callback) ->
  p = spawn command, args
  p.stderr.on 'data', (data) ->
    process.stderr.write data.toString()
  p.stdout.on 'data', (data) ->
    print data.toString()
  p.on 'exit', (code) ->
    callback?() if code is 0
