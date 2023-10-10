/**
 * @name openssl-c9fb704cf3af5524eb8e79961e31b60eee8c3c47-EVP_DecryptUpdate
 * @id cpp/openssl/c9fb704cf3af5524eb8e79961e31b60eee8c3c47/EVP-DecryptUpdate
 * @description openssl-c9fb704cf3af5524eb8e79961e31b60eee8c3c47-EVP_DecryptUpdate CVE-2021-23840
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vctx_686, Parameter vinl_687, Variable vb_690) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vinl_687
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(BitwiseAndExpr).getRightOperand().(ComplementExpr).getOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vb_690
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(BitwiseAndExpr).getRightOperand().(ComplementExpr).getOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(Literal).getValue()="2147483647"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vb_690
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getLeftOperand().(FunctionCall).getTarget().hasName("ERR_new")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(FunctionCall).getTarget().hasName("ERR_set_debug")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getArgument(0).(Literal).getValue()="6"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getArgument(1).(Literal).getValue()="202"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getArgument(2).(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getTarget().getName()="final_used"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_686)
}

predicate func_3(Parameter vctx_686, Parameter vout_686, Parameter voutl_686, Parameter vin_687, Parameter vinl_687) {
	exists(FunctionCall target_3 |
		target_3.getTarget().hasName("evp_EncryptDecryptUpdate")
		and target_3.getArgument(0).(VariableAccess).getTarget()=vctx_686
		and target_3.getArgument(1).(VariableAccess).getTarget()=vout_686
		and target_3.getArgument(2).(VariableAccess).getTarget()=voutl_686
		and target_3.getArgument(3).(VariableAccess).getTarget()=vin_687
		and target_3.getArgument(4).(VariableAccess).getTarget()=vinl_687)
}

predicate func_4(Parameter vout_686, Parameter vin_687, Variable vb_690) {
	exists(LogicalOrExpr target_4 |
		target_4.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vout_686
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vin_687
		and target_4.getAnOperand().(FunctionCall).getTarget().hasName("is_partially_overlapping")
		and target_4.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vout_686
		and target_4.getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vin_687
		and target_4.getAnOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vb_690
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getArgument(0).(Literal).getValue()="6"
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getArgument(1).(Literal).getValue()="162"
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getArgument(2).(Literal).getValue()="0"
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0")
}

from Function func, Parameter vctx_686, Parameter vout_686, Parameter voutl_686, Parameter vin_687, Parameter vinl_687, Variable vb_690, Variable v__func__
where
not func_0(vctx_686, vinl_687, vb_690)
and vctx_686.getType().hasName("EVP_CIPHER_CTX *")
and vinl_687.getType().hasName("int")
and func_3(vctx_686, vout_686, voutl_686, vin_687, vinl_687)
and vb_690.getType().hasName("unsigned int")
and func_4(vout_686, vin_687, vb_690)
and v__func__.getType().hasName("const char[18]")
and vctx_686.getParentScope+() = func
and vout_686.getParentScope+() = func
and voutl_686.getParentScope+() = func
and vin_687.getParentScope+() = func
and vinl_687.getParentScope+() = func
and vb_690.getParentScope+() = func
and not v__func__.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
