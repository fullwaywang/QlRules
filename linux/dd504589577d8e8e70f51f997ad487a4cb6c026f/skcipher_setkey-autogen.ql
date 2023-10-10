/**
 * @name linux-dd504589577d8e8e70f51f997ad487a4cb6c026f-skcipher_setkey
 * @id cpp/linux/dd504589577d8e8e70f51f997ad487a4cb6c026f/skcipher_setkey
 * @description linux-dd504589577d8e8e70f51f997ad487a4cb6c026f-skcipher_setkey 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vprivate_761, Function func) {
	exists(DeclStmt target_0 |
		target_0.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(VariableAccess).getTarget()=vprivate_761
		and func.getEntryPoint().(BlockStmt).getStmt(0)=target_0)
}

predicate func_1(Function func) {
	exists(DeclStmt target_1 |
		func.getEntryPoint().(BlockStmt).getStmt(1)=target_1)
}

predicate func_2(Parameter vkey_761, Parameter vkeylen_761, Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("int")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("crypto_skcipher_setkey")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="skcipher"
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("skcipher_tfm *")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vkey_761
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vkeylen_761
		and (func.getEntryPoint().(BlockStmt).getStmt(2)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(2).getFollowingStmt()=target_2))
}

predicate func_4(Function func) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="has_key"
		and target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("skcipher_tfm *")
		and target_4.getExpr().(AssignExpr).getRValue().(NotExpr).getOperand().(VariableAccess).getType().hasName("int")
		and (func.getEntryPoint().(BlockStmt).getStmt(3)=target_4 or func.getEntryPoint().(BlockStmt).getStmt(3).getFollowingStmt()=target_4))
}

from Function func, Parameter vprivate_761, Parameter vkey_761, Parameter vkeylen_761
where
not func_0(vprivate_761, func)
and not func_1(func)
and not func_2(vkey_761, vkeylen_761, func)
and not func_4(func)
and vprivate_761.getType().hasName("void *")
and vkey_761.getType().hasName("const u8 *")
and vkeylen_761.getType().hasName("unsigned int")
and vprivate_761.getParentScope+() = func
and vkey_761.getParentScope+() = func
and vkeylen_761.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
