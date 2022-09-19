import cpp

predicate func_0(Function func) {
	exists(StringLiteral target_0 |
		target_0.getValue()="tlsaad"
		and not target_0.getValue()="mackey"
		and target_0.getEnclosingFunction() = func)
}

from Function func
where
func_0(func)
select func
