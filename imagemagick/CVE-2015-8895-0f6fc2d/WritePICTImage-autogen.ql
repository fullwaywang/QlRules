/**
 * @name imagemagick-0f6fc2d5bf8f500820c3dbcf0d23ee14f2d9f734-WritePICTImage
 * @id cpp/imagemagick/0f6fc2d5bf8f500820c3dbcf0d23ee14f2d9f734/WritePICTImage
 * @description imagemagick-0f6fc2d5bf8f500820c3dbcf0d23ee14f2d9f734-coders/pict.c-WritePICTImage CVE-2015-8895
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Variable vrow_bytes_1_1652, Parameter vimage_1594, ExprStmt target_8, ExprStmt target_9) {
	exists(AssignExpr target_1 |
		target_1.getLValue().(VariableAccess).getTarget()=vrow_bytes_1_1652
		and target_1.getRValue().(PointerFieldAccess).getTarget().getName()="columns"
		and target_1.getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_1594
		and target_8.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_9.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Variable vrow_bytes_1_1652) {
	exists(AssignExpr target_2 |
		target_2.getLValue().(VariableAccess).getTarget()=vrow_bytes_1_1652
		and target_2.getRValue() instanceof MulExpr)
}

predicate func_3(Parameter vimage_1594, PointerFieldAccess target_3) {
		target_3.getTarget().getName()="columns"
		and target_3.getQualifier().(VariableAccess).getTarget()=vimage_1594
}

predicate func_4(Parameter vimage_1594, MulExpr target_4) {
		target_4.getLeftOperand().(Literal).getValue()="4"
		and target_4.getRightOperand().(PointerFieldAccess).getTarget().getName()="columns"
		and target_4.getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_1594
}

predicate func_6(Variable vrow_bytes_1_1652, Parameter vimage_1594, AssignExpr target_6) {
		target_6.getLValue().(VariableAccess).getTarget()=vrow_bytes_1_1652
		and target_6.getRValue().(BitwiseOrExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="columns"
		and target_6.getRValue().(BitwiseOrExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_1594
		and target_6.getRValue().(BitwiseOrExpr).getRightOperand().(HexLiteral).getValue()="32768"
}

predicate func_7(Variable vrow_bytes_1_1652, AssignExpr target_7) {
		target_7.getLValue().(VariableAccess).getTarget()=vrow_bytes_1_1652
		and target_7.getRValue().(BitwiseOrExpr).getLeftOperand() instanceof MulExpr
		and target_7.getRValue().(BitwiseOrExpr).getRightOperand().(HexLiteral).getValue()="32768"
}

predicate func_8(Parameter vimage_1594, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="right"
		and target_8.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="columns"
		and target_8.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_1594
}

predicate func_9(Parameter vimage_1594, ExprStmt target_9) {
		target_9.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="bottom"
		and target_9.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="rows"
		and target_9.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_1594
}

from Function func, Variable vrow_bytes_1_1652, Parameter vimage_1594, PointerFieldAccess target_3, MulExpr target_4, AssignExpr target_6, AssignExpr target_7, ExprStmt target_8, ExprStmt target_9
where
not func_1(vrow_bytes_1_1652, vimage_1594, target_8, target_9)
and not func_2(vrow_bytes_1_1652)
and func_3(vimage_1594, target_3)
and func_4(vimage_1594, target_4)
and func_6(vrow_bytes_1_1652, vimage_1594, target_6)
and func_7(vrow_bytes_1_1652, target_7)
and func_8(vimage_1594, target_8)
and func_9(vimage_1594, target_9)
and vrow_bytes_1_1652.getType().hasName("unsigned short")
and vimage_1594.getType().hasName("Image *")
and vrow_bytes_1_1652.getParentScope+() = func
and vimage_1594.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
