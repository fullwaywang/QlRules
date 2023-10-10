/**
 * @name expat-be4b1c06daba1849b8ff5e00bae5caf47f6c39fd-unknown_toUtf16
 * @id cpp/expat/be4b1c06daba1849b8ff5e00bae5caf47f6c39fd/unknown-toUtf16
 * @description expat-be4b1c06daba1849b8ff5e00bae5caf47f6c39fd-expat/lib/xmltok.c-unknown_toUtf16 CVE-2016-0718
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vfromLim_1338) {
	exists(RelationalOperation target_0 |
		 (target_0 instanceof GTExpr or target_0 instanceof LTExpr)
		and target_0.getLesserOperand() instanceof PointerDereferenceExpr
		and target_0.getGreaterOperand().(VariableAccess).getTarget()=vfromLim_1338
		and target_0.getParent().(LogicalAndExpr).getAnOperand() instanceof EqualityOperation
		and target_0.getParent().(LogicalAndExpr).getAnOperand() instanceof EqualityOperation)
}

predicate func_1(Parameter vtoLim_1339) {
	exists(RelationalOperation target_1 |
		 (target_1 instanceof GTExpr or target_1 instanceof LTExpr)
		and target_1.getLesserOperand() instanceof PointerDereferenceExpr
		and target_1.getGreaterOperand().(VariableAccess).getTarget()=vtoLim_1339
		and target_1.getParent().(LogicalAndExpr).getAnOperand() instanceof EqualityOperation
		and target_1.getParent().(LogicalAndExpr).getAnOperand() instanceof EqualityOperation)
}

predicate func_2(Parameter vfromP_1338, Parameter vfromLim_1338, Parameter vtoP_1339, Parameter vtoLim_1339, ExprStmt target_10, ExprStmt target_12, Function func) {
	exists(IfStmt target_2 |
		target_2.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vtoP_1339
		and target_2.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vtoLim_1339
		and target_2.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vfromP_1338
		and target_2.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vfromLim_1338
		and (func.getEntryPoint().(BlockStmt).getStmt(2)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(2).getFollowingStmt()=target_2)
		and target_10.getExpr().(PostfixIncrExpr).getOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_2.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation())
		and target_12.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_2.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation()))
}

predicate func_4(Parameter vfromP_1338, PointerDereferenceExpr target_4) {
		target_4.getOperand().(VariableAccess).getTarget()=vfromP_1338
}

predicate func_5(Parameter vtoP_1339, PointerDereferenceExpr target_5) {
		target_5.getOperand().(VariableAccess).getTarget()=vtoP_1339
}

predicate func_6(Parameter vfromLim_1338, VariableAccess target_6) {
		target_6.getTarget()=vfromLim_1338
}

predicate func_7(Parameter vtoLim_1339, VariableAccess target_7) {
		target_7.getTarget()=vtoLim_1339
}

/*predicate func_8(Parameter vfromLim_1338, Parameter vtoLim_1339, EqualityOperation target_8) {
		target_8.getAnOperand() instanceof PointerDereferenceExpr
		and target_8.getAnOperand().(VariableAccess).getTarget()=vfromLim_1338
		and target_8.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand() instanceof PointerDereferenceExpr
		and target_8.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vtoLim_1339
}

*/
/*predicate func_9(Parameter vfromLim_1338, Parameter vtoLim_1339, EqualityOperation target_9) {
		target_9.getAnOperand() instanceof PointerDereferenceExpr
		and target_9.getAnOperand().(VariableAccess).getTarget()=vtoLim_1339
		and target_9.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand() instanceof PointerDereferenceExpr
		and target_9.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vfromLim_1338
}

*/
predicate func_10(Parameter vfromP_1338, ExprStmt target_10) {
		target_10.getExpr().(PostfixIncrExpr).getOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vfromP_1338
}

predicate func_12(Parameter vtoP_1339, ExprStmt target_12) {
		target_12.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vtoP_1339
}

from Function func, Parameter vfromP_1338, Parameter vfromLim_1338, Parameter vtoP_1339, Parameter vtoLim_1339, PointerDereferenceExpr target_4, PointerDereferenceExpr target_5, VariableAccess target_6, VariableAccess target_7, ExprStmt target_10, ExprStmt target_12
where
not func_0(vfromLim_1338)
and not func_1(vtoLim_1339)
and not func_2(vfromP_1338, vfromLim_1338, vtoP_1339, vtoLim_1339, target_10, target_12, func)
and func_4(vfromP_1338, target_4)
and func_5(vtoP_1339, target_5)
and func_6(vfromLim_1338, target_6)
and func_7(vtoLim_1339, target_7)
and func_10(vfromP_1338, target_10)
and func_12(vtoP_1339, target_12)
and vfromP_1338.getType().hasName("const char **")
and vfromLim_1338.getType().hasName("const char *")
and vtoP_1339.getType().hasName("unsigned short **")
and vtoLim_1339.getType().hasName("const unsigned short *")
and vfromP_1338.getParentScope+() = func
and vfromLim_1338.getParentScope+() = func
and vtoP_1339.getParentScope+() = func
and vtoLim_1339.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
