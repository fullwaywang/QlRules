/**
 * @name libexpat-5290462a7ea1278a8d5c0d5b2860d4e244f997e4-parserCreate
 * @id cpp/libexpat/5290462a7ea1278a8d5c0d5b2860d4e244f997e4/parserCreate
 * @description libexpat-5290462a7ea1278a8d5c0d5b2860d4e244f997e4-parserCreate CVE-2022-43680
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vencodingName_972, Parameter vdtd_974, Variable vparser_975) {
	exists(IfStmt target_0 |
		target_0.getCondition().(VariableAccess).getTarget()=vdtd_974
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="m_dtd"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparser_975
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vencodingName_972
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="m_protocolEncodingName"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparser_975)
}

predicate func_2(Parameter vdtd_974, Variable vparser_975) {
	exists(AssignExpr target_2 |
		target_2.getLValue().(PointerFieldAccess).getTarget().getName()="m_dtd"
		and target_2.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparser_975
		and target_2.getRValue().(VariableAccess).getTarget()=vdtd_974)
}

predicate func_3(Variable vparser_975) {
	exists(PointerFieldAccess target_3 |
		target_3.getTarget().getName()="m_protocolEncodingName"
		and target_3.getQualifier().(VariableAccess).getTarget()=vparser_975)
}

from Function func, Parameter vencodingName_972, Parameter vdtd_974, Variable vparser_975
where
not func_0(vencodingName_972, vdtd_974, vparser_975)
and vencodingName_972.getType().hasName("const XML_Char *")
and vdtd_974.getType().hasName("DTD *")
and func_2(vdtd_974, vparser_975)
and vparser_975.getType().hasName("XML_Parser")
and func_3(vparser_975)
and vencodingName_972.getParentScope+() = func
and vdtd_974.getParentScope+() = func
and vparser_975.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
