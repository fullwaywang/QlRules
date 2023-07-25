/**
 * @name openssl-c9fb704cf3af5524eb8e79961e31b60eee8c3c47-evp_EncryptDecryptUpdate
 * @id cpp/openssl/c9fb704cf3af5524eb8e79961e31b60eee8c3c47/evp-EncryptDecryptUpdate
 * @description openssl-c9fb704cf3af5524eb8e79961e31b60eee8c3c47-evp_EncryptDecryptUpdate CVE-2021-23840
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vinl_462, Variable vi_464, Variable vj_464, Variable vbl_464) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(BitwiseAndExpr).getLeftOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vinl_462
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(BitwiseAndExpr).getLeftOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vj_464
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(BitwiseAndExpr).getRightOperand().(ComplementExpr).getOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vbl_464
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(BitwiseAndExpr).getRightOperand().(ComplementExpr).getOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(Literal).getValue()="2147483647"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vbl_464
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getLeftOperand().(FunctionCall).getTarget().hasName("ERR_new")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(FunctionCall).getTarget().hasName("ERR_set_debug")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getArgument(0).(Literal).getValue()="6"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getArgument(1).(Literal).getValue()="202"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getArgument(2).(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vbl_464
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vi_464
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vinl_462)
}

predicate func_3(Parameter vctx_460, Parameter vinl_462) {
	exists(AssignAddExpr target_3 |
		target_3.getLValue().(PointerFieldAccess).getTarget().getName()="buf_len"
		and target_3.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_460
		and target_3.getRValue().(VariableAccess).getTarget()=vinl_462)
}

predicate func_4(Variable vi_464, Variable vj_464, Variable vbl_464) {
	exists(AssignExpr target_4 |
		target_4.getLValue().(VariableAccess).getTarget()=vj_464
		and target_4.getRValue().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vbl_464
		and target_4.getRValue().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vi_464)
}

from Function func, Parameter vctx_460, Parameter vinl_462, Variable vi_464, Variable vj_464, Variable vbl_464, Variable v__func__
where
not func_0(vinl_462, vi_464, vj_464, vbl_464)
and vinl_462.getType().hasName("int")
and func_3(vctx_460, vinl_462)
and vi_464.getType().hasName("int")
and vj_464.getType().hasName("int")
and func_4(vi_464, vj_464, vbl_464)
and vbl_464.getType().hasName("int")
and v__func__.getType().hasName("const char[25]")
and vctx_460.getParentScope+() = func
and vinl_462.getParentScope+() = func
and vi_464.getParentScope+() = func
and vj_464.getParentScope+() = func
and vbl_464.getParentScope+() = func
and not v__func__.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
