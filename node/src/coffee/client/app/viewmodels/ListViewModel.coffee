define ["jquery", "knockout"], ($, ko) ->
  class ListViewModel
    itemList = undefined

    constructor: () ->
      @itemList = ko.observableArray()

    addItem: (item) ->
      @itemList.push item

    reset: ->
      @itemList.removeAll()
