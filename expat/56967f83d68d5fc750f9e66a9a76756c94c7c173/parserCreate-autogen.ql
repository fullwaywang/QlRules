/**
 * @name expat-56967f83d68d5fc750f9e66a9a76756c94c7c173-parserCreate
 * @id cpp/expat/56967f83d68d5fc750f9e66a9a76756c94c7c173/parserCreate
 * @description expat-56967f83d68d5fc750f9e66a9a76756c94c7c173-expat/lib/xmlparse.c-parserCreate CVE-2022-43680
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vdtd_974, Variable vparser_975, LogicalAndExpr target_1, ExprStmt target_2, ExprStmt target_3) {
	exists(IfStmt target_0 |
		target_0.getCondition().(VariableAccess).getTarget()=vdtd_974
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="m_dtd"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparser_975
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_1
		and target_2.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_0.getCondition().(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Variable vparser_975, LogicalAndExpr target_1) {
		target_1.getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="m_protocolEncodingName"
		and target_1.getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparser_975
}

predicate func_2(Parameter vdtd_974, Variable vparser_975, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="m_dtd"
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparser_975
		and target_2.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vdtd_974
}

predicate func_3(Variable vparser_975, ExprStmt target_3) {
		target_3.getExpr().(FunctionCall).getTarget().hasName("XML_ParserFree")
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vparser_975
}

from Function func, Parameter vdtd_974, Variable vparser_975, LogicalAndExpr target_1, ExprStmt target_2, ExprStmt target_3
where
not func_0(vdtd_974, vparser_975, target_1, target_2, target_3)
and func_1(vparser_975, target_1)
and func_2(vdtd_974, vparser_975, target_2)
and func_3(vparser_975, target_3)
and vdtd_974.getType().hasName("DTD *")
and vparser_975.getType().hasName("XML_Parser")
and vdtd_974.getParentScope+() = func
and vparser_975.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
