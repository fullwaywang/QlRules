/**
 * @name openssl-3f3582139fbb259a1c3cbb0a25236500a409bf26-EVP_EncryptUpdate
 * @id cpp/openssl/3f3582139fbb259a1c3cbb0a25236500a409bf26/EVP-EncryptUpdate
 * @description openssl-3f3582139fbb259a1c3cbb0a25236500a409bf26-crypto/evp/evp_enc.c-EVP_EncryptUpdate CVE-2016-2106
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vinl_304, Variable vi_306, Variable vbl_306, BlockStmt target_5, ExprStmt target_6, ExprStmt target_7, EqualityOperation target_8, AddressOfExpr target_9, ExprStmt target_10, ExprStmt target_11) {
	exists(RelationalOperation target_0 |
		 (target_0 instanceof GTExpr or target_0 instanceof LTExpr)
		and target_0.getGreaterOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vbl_306
		and target_0.getGreaterOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vi_306
		and target_0.getLesserOperand().(VariableAccess).getTarget()=vinl_304
		and target_0.getParent().(IfStmt).getThen()=target_5
		and target_6.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_0.getLesserOperand().(VariableAccess).getLocation())
		and target_0.getLesserOperand().(VariableAccess).getLocation().isBefore(target_7.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation())
		and target_8.getAnOperand().(VariableAccess).getLocation().isBefore(target_0.getGreaterOperand().(SubExpr).getRightOperand().(VariableAccess).getLocation())
		and target_0.getGreaterOperand().(SubExpr).getRightOperand().(VariableAccess).getLocation().isBefore(target_9.getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation())
		and target_10.getExpr().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_0.getGreaterOperand().(SubExpr).getLeftOperand().(VariableAccess).getLocation())
		and target_0.getGreaterOperand().(SubExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_11.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vi_306, VariableAccess target_1) {
		target_1.getTarget()=vi_306
}

predicate func_2(Parameter vinl_304, VariableAccess target_2) {
		target_2.getTarget()=vinl_304
}

predicate func_3(Variable vbl_306, BlockStmt target_5, VariableAccess target_3) {
		target_3.getTarget()=vbl_306
		and target_3.getParent().(LTExpr).getLesserOperand() instanceof AddExpr
		and target_3.getParent().(LTExpr).getParent().(IfStmt).getThen()=target_5
}

predicate func_4(Parameter vinl_304, Variable vi_306, Variable vbl_306, BlockStmt target_5, RelationalOperation target_4) {
		 (target_4 instanceof GTExpr or target_4 instanceof LTExpr)
		and target_4.getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vi_306
		and target_4.getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vinl_304
		and target_4.getGreaterOperand().(VariableAccess).getTarget()=vbl_306
		and target_4.getParent().(IfStmt).getThen()=target_5
}

predicate func_5(Parameter vinl_304, Variable vi_306, BlockStmt target_5) {
		target_5.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_5.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="buf"
		and target_5.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_306
		and target_5.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vinl_304
		and target_5.getStmt(1).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getTarget().getName()="buf_len"
		and target_5.getStmt(1).(ExprStmt).getExpr().(AssignAddExpr).getRValue().(VariableAccess).getTarget()=vinl_304
}

predicate func_6(Parameter vinl_304, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vinl_304
}

predicate func_7(Parameter vinl_304, Variable vi_306, ExprStmt target_7) {
		target_7.getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_7.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="buf"
		and target_7.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_306
		and target_7.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vinl_304
}

predicate func_8(Variable vi_306, EqualityOperation target_8) {
		target_8.getAnOperand().(VariableAccess).getTarget()=vi_306
		and target_8.getAnOperand().(Literal).getValue()="0"
}

predicate func_9(Variable vi_306, AddressOfExpr target_9) {
		target_9.getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="buf"
		and target_9.getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_306
}

predicate func_10(Variable vbl_306, ExprStmt target_10) {
		target_10.getExpr().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vbl_306
		and target_10.getExpr().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(SizeofExprOperator).getValue()="32"
		and target_10.getExpr().(ConditionalExpr).getThen().(Literal).getValue()="0"
		and target_10.getExpr().(ConditionalExpr).getElse().(CommaExpr).getLeftOperand().(FunctionCall).getTarget().hasName("OPENSSL_die")
		and target_10.getExpr().(ConditionalExpr).getElse().(CommaExpr).getLeftOperand().(FunctionCall).getArgument(0).(StringLiteral).getValue()="assertion failed: bl <= (int)sizeof(ctx->buf)"
		and target_10.getExpr().(ConditionalExpr).getElse().(CommaExpr).getLeftOperand().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_10.getExpr().(ConditionalExpr).getElse().(CommaExpr).getLeftOperand().(FunctionCall).getArgument(2) instanceof Literal
		and target_10.getExpr().(ConditionalExpr).getElse().(CommaExpr).getRightOperand().(Literal).getValue()="1"
}

predicate func_11(Variable vi_306, Variable vbl_306, ExprStmt target_11) {
		target_11.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vbl_306
		and target_11.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vi_306
}

from Function func, Parameter vinl_304, Variable vi_306, Variable vbl_306, VariableAccess target_1, VariableAccess target_2, VariableAccess target_3, RelationalOperation target_4, BlockStmt target_5, ExprStmt target_6, ExprStmt target_7, EqualityOperation target_8, AddressOfExpr target_9, ExprStmt target_10, ExprStmt target_11
where
not func_0(vinl_304, vi_306, vbl_306, target_5, target_6, target_7, target_8, target_9, target_10, target_11)
and func_1(vi_306, target_1)
and func_2(vinl_304, target_2)
and func_3(vbl_306, target_5, target_3)
and func_4(vinl_304, vi_306, vbl_306, target_5, target_4)
and func_5(vinl_304, vi_306, target_5)
and func_6(vinl_304, target_6)
and func_7(vinl_304, vi_306, target_7)
and func_8(vi_306, target_8)
and func_9(vi_306, target_9)
and func_10(vbl_306, target_10)
and func_11(vi_306, vbl_306, target_11)
and vinl_304.getType().hasName("int")
and vi_306.getType().hasName("int")
and vbl_306.getType().hasName("int")
and vinl_304.getParentScope+() = func
and vi_306.getParentScope+() = func
and vbl_306.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
