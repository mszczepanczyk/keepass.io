# keepass.io
#
# Created by Pascal Mathis at 04.12.2013
# License: GPLv3 (Please see LICENSE for more information)

class PyPackJS
  FMT_SEARCH_PATTERN = '(\\d+)?([AxcbBhHsfdiIlLqQ])'

  ###
  # Definition of all types
  ###
  TYPES =
    # Non-numeric types
    'A': { enc: 'encArray', dec: 'decArray' }
    's': { enc: 'encString', dec: 'decString' }
    'c': { enc: 'encChar', dec: 'decChar' }
    # Signed and unsigned byte
    'b': { enc: 'encInt', dec: 'decInt', size: 1, signed: true, min: -Math.pow(2, 7), max: Math.pow(2, 7) - 1 }
    'B': { enc: 'encInt', dec: 'decInt', size: 1, signed: false, min: -Math.pow(2, 7), max: Math.pow(2, 7) - 1 }
    # Signed and unsigned short
    'h': { enc: 'encInt', dec: 'decInt', size: 2, signed: true, min: -Math.pow(2, 15), max: Math.pow(2, 15) - 1 }
    'H': { enc: 'encInt', dec: 'decInt', size: 2, signed: false, min: -Math.pow(2, 15), max: Math.pow(2, 15) - 1 }
    # Signed and unsigned integer
    'i': { enc: 'encInt', dec: 'decInt', size: 4, signed: true, min: -Math.pow(2, 31), max: Math.pow(2, 31) - 1 }
    'I': { enc: 'encInt', dec: 'decInt', size: 4, signed: false, min: -Math.pow(2, 31), max: Math.pow(2, 31) - 1 }
    # Signed and unsigned long
    'q': { enc: 'encInt', dec: 'decInt', size: 8, signed: true, min: -Math.pow(2, 63), max: Math.pow(2, 63) - 1 }
    'Q': { enc: 'encInt', dec: 'decInt', size: 8, signed: false, min: -Math.pow(2, 63), max: Math.pow(2, 63) - 1 }
    # Floating point numbers
    'f': { enc: 'enc754', dec: 'dec754', size: 4, significand: 23, rt: Math.pow(2, -24) - Math.pow(2, -77) }
    'd': { enc: 'enc754', dec: 'dec754', size: 4, significand: 52, rt: 0 }

  ###
  # Array containing the length for each type
  ###
  TYPE_LENGHTS = {'A': 1, 'x': 1, 'c': 1, 'b': 1, 'B': 1, 'h': 2, 'H': 2, 's': 1, 'f': 4, 'd': 8, 'i': 4, 'I': 4, 'l': 4, 'L': 4, 'q': 8, 'Q': 8}

  constructor: ->
    @useBigEndian = false

  # Unpacks a buffer with binary data based on the given
  # format string. The following formats are available:
  #
  # c, b, B, h, H, i, I, l, L, f, d, q, Q
  #
  # To find more help about these formats, take a look into
  # the python documentation of 'pack'.
  unpack: (fmt, array, offset = 0) ->
    # Set the private big endian flag based on the format string.
    # By default, we assume big-endianness.
    @useBigEndian = (fmt.charAt(0) isnt '<')

    # Parse format string
    regExp = new RegExp(FMT_SEARCH_PATTERN, 'g')
    results = []
    while(match = regExp.exec(fmt))
      numberOfElements = if match[1] then parseInt(match[1]) else 1
      sizePerElement = TYPE_LENGHTS[match[2]]

      # Check if calculated size is bigger than array buffer
      if (offset + numberOfElements * sizePerElement) > array.length
        return undefined

      # Process octet array with the given types
      switch match[2]
        when 'A', 's'
          results.push(@[TYPES[match[2]].dec](array, offset, numberOfElements))
        when 'c', 'b', 'B', 'h', 'H', 'i', 'I', 'l', 'L', 'f', 'd', 'q', 'Q'
          elementType = TYPES[match[2]]
          results.push(@unpackSeries(elementType, numberOfElements, sizePerElement, array, offset))
        else
          throw new Error("Unknown format: #{match[2]}")

      offset += numberOfElements * sizePerElement

    # Return an array containing the parsed results
    return Array::concat.apply([], results)

  # Unpacks a series of elements with the same type
  unpackSeries: (elementType, numberOfElements, sizePerElement, array, offset) ->
    results = []
    index = 0
    while index < numberOfElements
      results.push(@[elementType.dec](elementType, array, offset + index * sizePerElement))
      index++

    return results

  # Decodes a (un)signed integer with N-bytes.
  # Endianness can be specified by modifying @useBigEndian
  decInt: (elementType, array, offset) ->
    # Set lsb and nsb according to endianness
    if @useBigEndian
      lsb = elementType.size - 1
      nsb = -1
    else
      lsb = 0
      nsb = 1

    # Calculate the offset where the number ends and set some variables
    stopPosition = lsb + nsb * elementType.size
    value = 0
    exponent = 1
    currentPosition = lsb

    # Read the number from the given buffer
    while currentPosition isnt stopPosition
      value += (array[offset + currentPosition] * exponent)
      exponent *= 256
      currentPosition += nsb

    # Convert to signed number if signed flag was set
    if elementType.signed and (value & Math.pow(2, elementType.size * 8 - 1))
      value -= Math.pow(2, elementType.size * 8)

    return value

  # Decodes simple ASCII character arrays
  decArray: (array, offset, length) ->
    return [array.slice(offset, offset + length)]

module.exports = new PyPackJS()