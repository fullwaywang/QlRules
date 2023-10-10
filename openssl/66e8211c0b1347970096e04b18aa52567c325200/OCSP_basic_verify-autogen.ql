/**
 * @name openssl-66e8211c0b1347970096e04b18aa52567c325200-OCSP_basic_verify
 * @id cpp/openssl/66e8211c0b1347970096e04b18aa52567c325200/OCSP-basic-verify
 * @description openssl-66e8211c0b1347970096e04b18aa52567c325200-OCSP_basic_verify CVE-2013-0166
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Variable vskey_92, Parameter vflags_76) {
	exists(IfStmt target_1 |
		target_1.getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vskey_92
		and target_1.getCondition().(LogicalOrExpr).getAnOperand() instanceof RelationalOperation
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0) instanceof Literal
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof Literal
		and target_1.getThen().(BlockStmt).getStmt(1).(GotoStmt).toString() = "goto ..."
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vflags_76
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="4")
}

predicate func_2(Variable vret_81, Variable vskey_92, Variable vOCSP_RESPDATA_it, Parameter vflags_76, Parameter vbs_75) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_81
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ASN1_item_verify")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vOCSP_RESPDATA_it
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="signatureAlgorithm"
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbs_75
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="signature"
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbs_75
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="tbsResponseData"
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbs_75
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vskey_92
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vflags_76
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="4")
}

predicate func_3(Variable vskey_92, Parameter vflags_76) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(FunctionCall).getTarget().hasName("EVP_PKEY_free")
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vskey_92
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vflags_76
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="4")
}

predicate func_4(Variable vret_81) {
	exists(RelationalOperation target_4 |
		 (target_4 instanceof GEExpr or target_4 instanceof LEExpr)
		and target_4.getLesserOperand().(VariableAccess).getTarget()=vret_81
		and target_4.getGreaterOperand().(Literal).getValue()="0"
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0) instanceof Literal
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof Literal)
}

predicate func_5(Variable vret_81, Variable vskey_92, Variable vOCSP_RESPDATA_it, Parameter vbs_75) {
	exists(AssignExpr target_5 |
		target_5.getLValue().(VariableAccess).getTarget()=vret_81
		and target_5.getRValue().(FunctionCall).getTarget().hasName("ASN1_item_verify")
		and target_5.getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vOCSP_RESPDATA_it
		and target_5.getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="signatureAlgorithm"
		and target_5.getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbs_75
		and target_5.getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="signature"
		and target_5.getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbs_75
		and target_5.getRValue().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="tbsResponseData"
		and target_5.getRValue().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbs_75
		and target_5.getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vskey_92)
}

predicate func_6(Variable vskey_92) {
	exists(FunctionCall target_6 |
		target_6.getTarget().hasName("EVP_PKEY_free")
		and target_6.getArgument(0).(VariableAccess).getTarget()=vskey_92)
}

from Function func, Variable vret_81, Variable vskey_92, Variable vOCSP_RESPDATA_it, Parameter vflags_76, Parameter vbs_75
where
not func_1(vskey_92, vflags_76)
and func_2(vret_81, vskey_92, vOCSP_RESPDATA_it, vflags_76, vbs_75)
and func_3(vskey_92, vflags_76)
and func_4(vret_81)
and vret_81.getType().hasName("int")
and vskey_92.getType().hasName("EVP_PKEY *")
and func_5(vret_81, vskey_92, vOCSP_RESPDATA_it, vbs_75)
and func_6(vskey_92)
and vOCSP_RESPDATA_it.getType().hasName("const ASN1_ITEM")
and vflags_76.getType().hasName("unsigned long")
and vbs_75.getType().hasName("OCSP_BASICRESP *")
and vret_81.getParentScope+() = func
and vskey_92.getParentScope+() = func
and not vOCSP_RESPDATA_it.getParentScope+() = func
and vflags_76.getParentScope+() = func
and vbs_75.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
