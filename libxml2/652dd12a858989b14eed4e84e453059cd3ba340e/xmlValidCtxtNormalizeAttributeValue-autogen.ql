/**
 * @name libxml2-652dd12a858989b14eed4e84e453059cd3ba340e-xmlValidCtxtNormalizeAttributeValue
 * @id cpp/libxml2/652dd12a858989b14eed4e84e453059cd3ba340e/xmlValidCtxtNormalizeAttributeValue
 * @description libxml2-652dd12a858989b14eed4e84e453059cd3ba340e-xmlValidCtxtNormalizeAttributeValue CVE-2022-23308
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vret_4031) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("xmlValidNormalizeString")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vret_4031)
}

predicate func_2(Function func) {
	exists(VariableDeclarationEntry target_2 |
		target_2.getType() instanceof PointerType
		and target_2.getDeclaration().getParentScope+() = func)
}

predicate func_3(Function func) {
	exists(DeclStmt target_3 |
		target_3.getDeclarationEntry(0).(VariableDeclarationEntry).getType() instanceof PointerType
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_3)
}

predicate func_4(Parameter vvalue_4030, Variable vsrc_4032) {
	exists(AssignExpr target_4 |
		target_4.getLValue().(VariableAccess).getTarget()=vsrc_4032
		and target_4.getRValue().(VariableAccess).getTarget()=vvalue_4030)
}

predicate func_5(Variable vret_4031, Variable vdst_4031, Function func) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vdst_4031
		and target_5.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vret_4031
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_5)
}

predicate func_6(Variable vsrc_4032, Function func) {
	exists(WhileStmt target_6 |
		target_6.getCondition().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vsrc_4032
		and target_6.getCondition().(EqualityOperation).getAnOperand().(HexLiteral).getValue()="32"
		and target_6.getStmt().(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vsrc_4032
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_6)
}

predicate func_7(Variable vdst_4031, Variable vsrc_4032, Function func) {
	exists(WhileStmt target_7 |
		target_7.getCondition().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vsrc_4032
		and target_7.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_7.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(WhileStmt).getStmt().(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vsrc_4032
		and target_7.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vdst_4031
		and target_7.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(HexLiteral).getValue()="32"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_7)
}

predicate func_12(Variable vdst_4031, Function func) {
	exists(ExprStmt target_12 |
		target_12.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vdst_4031
		and target_12.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_12)
}

from Function func, Parameter vvalue_4030, Variable vret_4031, Variable vdst_4031, Variable vsrc_4032
where
not func_0(vret_4031)
and func_2(func)
and func_3(func)
and func_4(vvalue_4030, vsrc_4032)
and func_5(vret_4031, vdst_4031, func)
and func_6(vsrc_4032, func)
and func_7(vdst_4031, vsrc_4032, func)
and func_12(vdst_4031, func)
and vvalue_4030.getType().hasName("const xmlChar *")
and vret_4031.getType().hasName("xmlChar *")
and vsrc_4032.getType().hasName("const xmlChar *")
and vvalue_4030.getParentScope+() = func
and vret_4031.getParentScope+() = func
and vdst_4031.getParentScope+() = func
and vsrc_4032.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
