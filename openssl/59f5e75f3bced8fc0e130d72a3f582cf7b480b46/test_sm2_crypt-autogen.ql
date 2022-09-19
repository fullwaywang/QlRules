import cpp

predicate func_0(Function func) {
	exists(StringLiteral target_0 |
		target_0.getValue()="sm2_plaintext_size(key, digest, ctext_len, &ptext_len)"
		and not target_0.getValue()="sm2_plaintext_size(ctext, ctext_len, &ptext_len)"
		and target_0.getEnclosingFunction() = func)
}

from Function func
where
func_0(func)
select func
