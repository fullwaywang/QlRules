/**
 * @name libjpeg-turbo-f8cca819a4fb42aafa5f70df43c45e8c416d716f-jinit_write_bmp
 * @id cpp/libjpeg-turbo/f8cca819a4fb42aafa5f70df43c45e8c416d716f/jinit-write-bmp
 * @description libjpeg-turbo-f8cca819a4fb42aafa5f70df43c45e8c416d716f-wrbmp.c-jinit_write_bmp CVE-2018-19664
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vcinfo_483, BlockStmt target_2, IfStmt target_3, LogicalOrExpr target_1) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="quantize_colors"
		and target_0.getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcinfo_483
		and target_0.getAnOperand() instanceof LogicalOrExpr
		and target_0.getParent().(IfStmt).getThen()=target_2
		and target_3.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vcinfo_483, BlockStmt target_2, LogicalOrExpr target_1) {
		target_1.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="out_color_space"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcinfo_483
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="out_color_space"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcinfo_483
		and target_1.getParent().(IfStmt).getThen()=target_2
}

predicate func_2(BlockStmt target_2) {
		target_2.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="put_pixel_rows"
		and target_2.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="pub"
}

predicate func_3(Parameter vcinfo_483, IfStmt target_3) {
		target_3.getCondition().(PointerFieldAccess).getTarget().getName()="quantize_colors"
		and target_3.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcinfo_483
		and target_3.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="put_pixel_rows"
		and target_3.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="pub"
		and target_3.getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="put_pixel_rows"
		and target_3.getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="pub"
}

from Function func, Parameter vcinfo_483, LogicalOrExpr target_1, BlockStmt target_2, IfStmt target_3
where
not func_0(vcinfo_483, target_2, target_3, target_1)
and func_1(vcinfo_483, target_2, target_1)
and func_2(target_2)
and func_3(vcinfo_483, target_3)
and vcinfo_483.getType().hasName("j_decompress_ptr")
and vcinfo_483.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
