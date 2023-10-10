/**
 * @name imagemagick-98a2cceae0dceccbfe54051167c2c80be1f13c3f-WriteMPCImage
 * @id cpp/imagemagick/98a2cceae0dceccbfe54051167c2c80be1f13c3f/WriteMPCImage
 * @description imagemagick-98a2cceae0dceccbfe54051167c2c80be1f13c3f-coders/mpc.c-WriteMPCImage CVE-2018-14434
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vcolormap_1453, ExprStmt target_3, ExprStmt target_4) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcolormap_1453
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("RelinquishMagickMemory")
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcolormap_1453
		and target_3.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation())
		and target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_4.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation()))
}

predicate func_2(VariableAccess target_5, Function func, EmptyStmt target_2) {
		target_2.toString() = ";"
		and target_2.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_5
		and target_2.getEnclosingFunction() = func
}

predicate func_3(Variable vcolormap_1453, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vcolormap_1453
}

predicate func_4(Variable vcolormap_1453, ExprStmt target_4) {
		target_4.getExpr().(FunctionCall).getTarget().hasName("WriteBlob")
		and target_4.getExpr().(FunctionCall).getArgument(1).(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="colors"
		and target_4.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vcolormap_1453
}

predicate func_5(Variable vdepth_1145, VariableAccess target_5) {
		target_5.getTarget()=vdepth_1145
}

from Function func, Variable vdepth_1145, Variable vcolormap_1453, EmptyStmt target_2, ExprStmt target_3, ExprStmt target_4, VariableAccess target_5
where
not func_0(vcolormap_1453, target_3, target_4)
and func_2(target_5, func, target_2)
and func_3(vcolormap_1453, target_3)
and func_4(vcolormap_1453, target_4)
and func_5(vdepth_1145, target_5)
and vdepth_1145.getType().hasName("size_t")
and vcolormap_1453.getType().hasName("unsigned char *")
and vdepth_1145.getParentScope+() = func
and vcolormap_1453.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
