{
	'targets': [
		{
			'target_name': 'kpion',
			'sources': [
				'kpion.cc'
			],
			'cflags_cc!': [ '-fno-rtti', '-Wunused-variable' ],
			'cflags_cc': [ '-O3', '-fexceptions', '-g', '-Werror' ],
			'libraries': [ '-lcryptopp' ]
		}
	]
}
