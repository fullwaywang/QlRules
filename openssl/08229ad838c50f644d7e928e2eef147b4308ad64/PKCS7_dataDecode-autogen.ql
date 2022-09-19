import cpp

predicate func_0(Function func) {
	exists(Literal target_0 |
		target_0.getValue()="373"
		and not target_0.getValue()="376"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Function func) {
	exists(Literal target_1 |
		target_1.getValue()="378"
		and not target_1.getValue()="381"
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Function func) {
	exists(Literal target_2 |
		target_2.getValue()="396"
		and not target_2.getValue()="399"
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Function func) {
	exists(Literal target_3 |
		target_3.getValue()="410"
		and not target_3.getValue()="413"
		and target_3.getEnclosingFunction() = func)
}

predicate func_4(Function func) {
	exists(Literal target_4 |
		target_4.getValue()="422"
		and not target_4.getValue()="425"
		and target_4.getEnclosingFunction() = func)
}

predicate func_5(Function func) {
	exists(Literal target_5 |
		target_5.getValue()="427"
		and not target_5.getValue()="430"
		and target_5.getEnclosingFunction() = func)
}

predicate func_6(Function func) {
	exists(Literal target_6 |
		target_6.getValue()="433"
		and not target_6.getValue()="436"
		and target_6.getEnclosingFunction() = func)
}

predicate func_7(Function func) {
	exists(Literal target_7 |
		target_7.getValue()="442"
		and not target_7.getValue()="445"
		and target_7.getEnclosingFunction() = func)
}

predicate func_8(Function func) {
	exists(Literal target_8 |
		target_8.getValue()="450"
		and not target_8.getValue()="453"
		and target_8.getEnclosingFunction() = func)
}

predicate func_9(Function func) {
	exists(Literal target_9 |
		target_9.getValue()="465"
		and not target_9.getValue()="468"
		and target_9.getEnclosingFunction() = func)
}

predicate func_10(Function func) {
	exists(Literal target_10 |
		target_10.getValue()="488"
		and not target_10.getValue()="491"
		and target_10.getEnclosingFunction() = func)
}

predicate func_11(Variable vevp_cipher) {
	exists(FunctionCall target_11 |
		target_11.getTarget().hasName("EVP_CIPHER_key_length")
		and target_11.getType().hasName("int")
		and target_11.getArgument(0).(VariableAccess).getTarget()=vevp_cipher)
}

from Function func, Variable vevp_cipher
where
func_0(func)
and func_1(func)
and func_2(func)
and func_3(func)
and func_4(func)
and func_5(func)
and func_6(func)
and func_7(func)
and func_8(func)
and func_9(func)
and func_10(func)
and not func_11(vevp_cipher)
and vevp_cipher.getType().hasName("const EVP_CIPHER *")
and vevp_cipher.getParentScope+() = func
select func, vevp_cipher
