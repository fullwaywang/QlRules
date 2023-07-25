/**
 * @name openssl-6a51b9e1d0cf0bf8515f7201b68fb0a3482b3dc1-EVP_DecryptUpdate
 * @id cpp/openssl/6a51b9e1d0cf0bf8515f7201b68fb0a3482b3dc1/EVP-DecryptUpdate
 * @description openssl-6a51b9e1d0cf0bf8515f7201b68fb0a3482b3dc1-EVP_DecryptUpdate CVE-2021-23840
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vctx_450, Parameter vinl_451, Variable vb_454) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vinl_451
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(BitwiseAndExpr).getRightOperand().(ComplementExpr).getOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vb_454
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(BitwiseAndExpr).getRightOperand().(ComplementExpr).getOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(Literal).getValue()="2147483647"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vb_454
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="6"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="166"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="184"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof Literal
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getTarget().getName()="final_used"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_450)
}

predicate func_3(Parameter vctx_450, Parameter vout_450, Parameter voutl_450, Parameter vin_451, Parameter vinl_451) {
	exists(FunctionCall target_3 |
		target_3.getTarget().hasName("evp_EncryptDecryptUpdate")
		and target_3.getArgument(0).(VariableAccess).getTarget()=vctx_450
		and target_3.getArgument(1).(VariableAccess).getTarget()=vout_450
		and target_3.getArgument(2).(VariableAccess).getTarget()=voutl_450
		and target_3.getArgument(3).(VariableAccess).getTarget()=vin_451
		and target_3.getArgument(4).(VariableAccess).getTarget()=vinl_451)
}

predicate func_4(Parameter vout_450, Parameter vin_451, Variable vb_454) {
	exists(LogicalOrExpr target_4 |
		target_4.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vout_450
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vin_451
		and target_4.getAnOperand().(FunctionCall).getTarget().hasName("is_partially_overlapping")
		and target_4.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vout_450
		and target_4.getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vin_451
		and target_4.getAnOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vb_454
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="6"
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="166"
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="162"
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof Literal)
}

from Function func, Parameter vctx_450, Parameter vout_450, Parameter voutl_450, Parameter vin_451, Parameter vinl_451, Variable vb_454
where
not func_0(vctx_450, vinl_451, vb_454)
and vctx_450.getType().hasName("EVP_CIPHER_CTX *")
and vinl_451.getType().hasName("int")
and func_3(vctx_450, vout_450, voutl_450, vin_451, vinl_451)
and vb_454.getType().hasName("unsigned int")
and func_4(vout_450, vin_451, vb_454)
and vctx_450.getParentScope+() = func
and vout_450.getParentScope+() = func
and voutl_450.getParentScope+() = func
and vin_451.getParentScope+() = func
and vinl_451.getParentScope+() = func
and vb_454.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
