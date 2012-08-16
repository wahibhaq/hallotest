

{print} = require 'sys'
{spawn} = require 'child_process'
{readdir} = require 'fs'


task 'end', 'execute node app (development)', ->
  exec ''

ccc = commonCoffeeCordova = (callback) ->
  exec 'coffee', ['-c', '-o', 'android/assets/js/app/', 'common/src/client/'], callback


ccn = commonCoffeeNode = (callback) ->
  exec 'coffee', ['-c', '-o', 'node/assets/js/app/', 'common/src/client/'], callback


cc = coffeeCordova = (callback) ->
  exec 'coffee', ['-c', '-o', 'android/assets/js/app/', 'common/src/client/'], callback

task 'cn', 'compile src coffee to node assets', ->
  coffeeNode()

task 'cc', 'compile src coffee to cordova assets', ->
  coffeeCordova()

task 'bc', 'build all cordova assets', ->
  coffeeCordova jadeCordova()


task 'bn', 'build all node assets', ->
  commonCoffeeNode  jadeNode()



task 'watch', 'Watch src/ for coffee changes', ->
  exec 'coffee', ['-w', '-c', '-o', 'assets/js/app/', 'src/coffee/client']
 
optimize = (callback) ->
  exec 'node', ['build/r.js', '-o','build/app.build.js']

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
