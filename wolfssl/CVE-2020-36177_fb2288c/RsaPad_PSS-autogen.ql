/**
 * @name wolfssl-fb2288c46dd4c864b78f00a47a364b96a09a5c0f-RsaPad_PSS
 * @id cpp/wolfssl/fb2288c46dd4c864b78f00a47a364b96a09a5c0f/RsaPad-PSS
 * @description wolfssl-fb2288c46dd4c864b78f00a47a364b96a09a5c0f-wolfcrypt/src/rsa.c-RsaPad_PSS CVE-2020-36177
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vinputLen_1111, Parameter vpkcsBlockLen_1112, Parameter vsaltLen_1113, Parameter vheap_1113, Variable vm_1117, EqualityOperation target_7, ExprStmt target_8, ExprStmt target_9, RelationalOperation target_10, ExprStmt target_11, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vpkcsBlockLen_1112
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vinputLen_1111
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vsaltLen_1113
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("byte *")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(CommaExpr).getLeftOperand().(CommaExpr).getLeftOperand().(VariableAccess).getTarget()=vheap_1113
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(CommaExpr).getRightOperand().(FunctionCall).getTarget().hasName("wolfSSL_Malloc")
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("byte *")
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vm_1117
		and target_0.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("byte *")
		and target_0.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr() instanceof AssignExpr
		and (func.getEntryPoint().(BlockStmt).getStmt(14)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(14).getFollowingStmt()=target_0)
		and target_7.getAnOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation())
		and target_8.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(SubExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_9.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(SubExpr).getLeftOperand().(VariableAccess).getLocation())
		and target_10.getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(CommaExpr).getLeftOperand().(CommaExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(VariableAccess).getLocation()))
}

/*predicate func_2(Parameter vinputLen_1111, Parameter vsaltLen_1113, Parameter vheap_1113, Variable vs_1118, ExprStmt target_12, RelationalOperation target_13, ExprStmt target_11) {
	exists(CommaExpr target_2 |
		target_2.getLeftOperand().(CommaExpr).getLeftOperand().(VariableAccess).getTarget()=vheap_1113
		and target_2.getRightOperand().(FunctionCall).getTarget().hasName("wolfSSL_Malloc")
		and target_2.getRightOperand().(FunctionCall).getArgument(0).(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vinputLen_1111
		and target_2.getRightOperand().(FunctionCall).getArgument(0).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vsaltLen_1113
		and target_2.getParent().(AssignExpr).getRValue() = target_2
		and target_2.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vs_1118
		and target_2.getRightOperand().(FunctionCall).getArgument(0).(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_12.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation())
		and target_2.getRightOperand().(FunctionCall).getArgument(0).(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_13.getGreaterOperand().(VariableAccess).getLocation())
		and target_2.getLeftOperand().(CommaExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(VariableAccess).getLocation()))
}

*/
predicate func_3(Variable vm_1117, Variable vs_1118, ExprStmt target_14) {
	exists(AssignExpr target_3 |
		target_3.getLValue().(VariableAccess).getTarget()=vs_1118
		and target_3.getRValue().(VariableAccess).getTarget()=vm_1117
		and target_3.getLValue().(VariableAccess).getLocation().isBefore(target_14.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_4(Function func) {
	exists(IfStmt target_4 |
		target_4.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("byte *")
		and target_4.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_4.getThen().(BlockStmt).getStmt(0).(BlockStmt).getStmt(1).(IfStmt).getCondition().(VariableAccess).getType().hasName("void *")
		and target_4.getThen().(BlockStmt).getStmt(0).(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("wolfSSL_Free")
		and target_4.getThen().(BlockStmt).getStmt(0).(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("void *")
		and target_4.getThen().(BlockStmt).getStmt(1).(EmptyStmt).toString() = ";"
		and (func.getEntryPoint().(BlockStmt).getStmt(25)=target_4 or func.getEntryPoint().(BlockStmt).getStmt(25).getFollowingStmt()=target_4))
}

/*predicate func_5(Parameter vpkcsBlock_1111, Variable vm_1117, Variable vs_1118, AssignExpr target_5) {
		target_5.getLValue().(VariableAccess).getTarget()=vm_1117
		and target_5.getRValue().(VariableAccess).getTarget()=vpkcsBlock_1111
		and target_5.getParent().(AssignExpr).getRValue() = target_5
		and target_5.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vs_1118
}

*/
/*predicate func_6(Parameter vpkcsBlock_1111, Variable vm_1117, Variable vs_1118, VariableAccess target_6) {
		target_6.getTarget()=vs_1118
		and target_6.getParent().(AssignExpr).getLValue() = target_6
		and target_6.getParent().(AssignExpr).getRValue().(AssignExpr).getLValue().(VariableAccess).getTarget()=vm_1117
		and target_6.getParent().(AssignExpr).getRValue().(AssignExpr).getRValue().(VariableAccess).getTarget()=vpkcsBlock_1111
}

*/
predicate func_7(Parameter vinputLen_1111, EqualityOperation target_7) {
		target_7.getAnOperand().(VariableAccess).getTarget()=vinputLen_1111
}

predicate func_8(Parameter vpkcsBlockLen_1112, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vpkcsBlockLen_1112
		and target_8.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
}

predicate func_9(Parameter vpkcsBlock_1111, Parameter vpkcsBlockLen_1112, ExprStmt target_9) {
		target_9.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vpkcsBlock_1111
		and target_9.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vpkcsBlockLen_1112
		and target_9.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(SubExpr).getRightOperand().(Literal).getValue()="1"
}

predicate func_10(Parameter vpkcsBlockLen_1112, Parameter vsaltLen_1113, RelationalOperation target_10) {
		 (target_10 instanceof GTExpr or target_10 instanceof LTExpr)
		and target_10.getLesserOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vpkcsBlockLen_1112
		and target_10.getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vsaltLen_1113
		and target_10.getGreaterOperand().(AddExpr).getAnOperand().(Literal).getValue()="2"
}

predicate func_11(Parameter vpkcsBlock_1111, Parameter vheap_1113, ExprStmt target_11) {
		target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("RsaMGF")
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vpkcsBlock_1111
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vpkcsBlock_1111
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vheap_1113
}

predicate func_12(Parameter vinputLen_1111, Variable vm_1117, ExprStmt target_12) {
		target_12.getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_12.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vm_1117
		and target_12.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vinputLen_1111
}

predicate func_13(Parameter vsaltLen_1113, RelationalOperation target_13) {
		 (target_13 instanceof GTExpr or target_13 instanceof LTExpr)
		and target_13.getGreaterOperand().(VariableAccess).getTarget()=vsaltLen_1113
		and target_13.getLesserOperand().(Literal).getValue()="0"
}

predicate func_14(Parameter vpkcsBlock_1111, Variable vm_1117, Variable vs_1118, ExprStmt target_14) {
		target_14.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("wc_Hash")
		and target_14.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vs_1118
		and target_14.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vm_1117
		and target_14.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vs_1118
		and target_14.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vpkcsBlock_1111
}

from Function func, Parameter vinputLen_1111, Parameter vpkcsBlock_1111, Parameter vpkcsBlockLen_1112, Parameter vsaltLen_1113, Parameter vheap_1113, Variable vm_1117, Variable vs_1118, EqualityOperation target_7, ExprStmt target_8, ExprStmt target_9, RelationalOperation target_10, ExprStmt target_11, ExprStmt target_12, RelationalOperation target_13, ExprStmt target_14
where
not func_0(vinputLen_1111, vpkcsBlockLen_1112, vsaltLen_1113, vheap_1113, vm_1117, target_7, target_8, target_9, target_10, target_11, func)
and not func_3(vm_1117, vs_1118, target_14)
and not func_4(func)
and func_7(vinputLen_1111, target_7)
and func_8(vpkcsBlockLen_1112, target_8)
and func_9(vpkcsBlock_1111, vpkcsBlockLen_1112, target_9)
and func_10(vpkcsBlockLen_1112, vsaltLen_1113, target_10)
and func_11(vpkcsBlock_1111, vheap_1113, target_11)
and func_12(vinputLen_1111, vm_1117, target_12)
and func_13(vsaltLen_1113, target_13)
and func_14(vpkcsBlock_1111, vm_1117, vs_1118, target_14)
and vinputLen_1111.getType().hasName("word32")
and vpkcsBlock_1111.getType().hasName("byte *")
and vpkcsBlockLen_1112.getType().hasName("word32")
and vsaltLen_1113.getType().hasName("int")
and vheap_1113.getType().hasName("void *")
and vm_1117.getType().hasName("byte *")
and vs_1118.getType().hasName("byte *")
and vinputLen_1111.getParentScope+() = func
and vpkcsBlock_1111.getParentScope+() = func
and vpkcsBlockLen_1112.getParentScope+() = func
and vsaltLen_1113.getParentScope+() = func
and vheap_1113.getParentScope+() = func
and vm_1117.getParentScope+() = func
and vs_1118.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
