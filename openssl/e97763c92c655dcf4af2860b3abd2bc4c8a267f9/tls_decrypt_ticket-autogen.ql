/**
 * @name openssl-e97763c92c655dcf4af2860b3abd2bc4c8a267f9-tls_decrypt_ticket
 * @id cpp/openssl/e97763c92c655dcf4af2860b3abd2bc4c8a267f9/tls-decrypt-ticket
 * @description openssl-e97763c92c655dcf4af2860b3abd2bc4c8a267f9-ssl/t1_lib.c-tls_decrypt_ticket CVE-2016-6302
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Literal target_0) {
		target_0.getValue()="48"
		and not target_0.getValue()="16"
		and target_0.getParent().(LTExpr).getParent().(IfStmt).getCondition() instanceof RelationalOperation
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Parameter veticklen_2961, Variable vmlen_2967, Variable vctx_2970, ReturnStmt target_7, ExprStmt target_8) {
	exists(RelationalOperation target_1 |
		 (target_1 instanceof GEExpr or target_1 instanceof LEExpr)
		and target_1.getLesserOperand().(VariableAccess).getTarget()=veticklen_2961
		and target_1.getGreaterOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(Literal).getValue()="16"
		and target_1.getGreaterOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(FunctionCall).getTarget().hasName("EVP_CIPHER_CTX_iv_length")
		and target_1.getGreaterOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctx_2970
		and target_1.getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vmlen_2967
		and target_1.getParent().(IfStmt).getThen()=target_7
		and target_1.getLesserOperand().(VariableAccess).getLocation().isBefore(target_8.getExpr().(AssignSubExpr).getLValue().(VariableAccess).getLocation()))
}

predicate func_2(Variable vret_2967, RelationalOperation target_6) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_2967
		and target_2.getExpr().(AssignExpr).getRValue() instanceof Literal
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_6)
}

predicate func_3(RelationalOperation target_6, Function func) {
	exists(GotoStmt target_3 |
		target_3.toString() = "goto ..."
		and target_3.getName() ="err"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_3
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_6
		and target_3.getEnclosingFunction() = func)
}

predicate func_4(Parameter veticklen_2961, ReturnStmt target_7, VariableAccess target_4) {
		target_4.getTarget()=veticklen_2961
		and target_4.getParent().(LTExpr).getGreaterOperand() instanceof Literal
		and target_4.getParent().(LTExpr).getParent().(IfStmt).getThen()=target_7
}

predicate func_6(Parameter veticklen_2961, ReturnStmt target_7, RelationalOperation target_6) {
		 (target_6 instanceof GTExpr or target_6 instanceof LTExpr)
		and target_6.getLesserOperand().(VariableAccess).getTarget()=veticklen_2961
		and target_6.getGreaterOperand() instanceof Literal
		and target_6.getParent().(IfStmt).getThen()=target_7
}

predicate func_7(RelationalOperation target_6, Function func, ReturnStmt target_7) {
		target_7.getExpr() instanceof Literal
		and target_7.getParent().(IfStmt).getCondition()=target_6
		and target_7.getEnclosingFunction() = func
}

predicate func_8(Parameter veticklen_2961, Variable vmlen_2967, ExprStmt target_8) {
		target_8.getExpr().(AssignSubExpr).getLValue().(VariableAccess).getTarget()=veticklen_2961
		and target_8.getExpr().(AssignSubExpr).getRValue().(VariableAccess).getTarget()=vmlen_2967
}

from Function func, Parameter veticklen_2961, Variable vmlen_2967, Variable vret_2967, Variable vctx_2970, Literal target_0, VariableAccess target_4, RelationalOperation target_6, ReturnStmt target_7, ExprStmt target_8
where
func_0(func, target_0)
and not func_1(veticklen_2961, vmlen_2967, vctx_2970, target_7, target_8)
and not func_2(vret_2967, target_6)
and not func_3(target_6, func)
and func_4(veticklen_2961, target_7, target_4)
and func_6(veticklen_2961, target_7, target_6)
and func_7(target_6, func, target_7)
and func_8(veticklen_2961, vmlen_2967, target_8)
and veticklen_2961.getType().hasName("int")
and vmlen_2967.getType().hasName("int")
and vret_2967.getType().hasName("int")
and vctx_2970.getType().hasName("EVP_CIPHER_CTX *")
and veticklen_2961.getParentScope+() = func
and vmlen_2967.getParentScope+() = func
and vret_2967.getParentScope+() = func
and vctx_2970.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
