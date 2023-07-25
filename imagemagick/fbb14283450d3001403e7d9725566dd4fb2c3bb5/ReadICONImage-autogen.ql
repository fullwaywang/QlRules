/**
 * @name imagemagick-fbb14283450d3001403e7d9725566dd4fb2c3bb5-ReadICONImage
 * @id cpp/imagemagick/fbb14283450d3001403e7d9725566dd4fb2c3bb5/ReadICONImage
 * @description imagemagick-fbb14283450d3001403e7d9725566dd4fb2c3bb5-coders/icon.c-ReadICONImage CVE-2017-9405
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vicon_colormap_444, EqualityOperation target_3, ExprStmt target_4) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vicon_colormap_444
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("RelinquishMagickMemory")
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vicon_colormap_444
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(11)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3
		and target_4.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation()))
}

predicate func_1(Variable vicon_colormap_444, EqualityOperation target_3, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vicon_colormap_444
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("RelinquishMagickMemory")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vicon_colormap_444
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3
}

predicate func_2(EqualityOperation target_3, Function func, EmptyStmt target_2) {
		target_2.toString() = ";"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3
		and target_2.getEnclosingFunction() = func
}

predicate func_3(EqualityOperation target_3) {
		target_3.getAnOperand().(PointerFieldAccess).getTarget().getName()="storage_class"
}

predicate func_4(Variable vicon_colormap_444, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vicon_colormap_444
}

from Function func, Variable vicon_colormap_444, ExprStmt target_1, EmptyStmt target_2, EqualityOperation target_3, ExprStmt target_4
where
not func_0(vicon_colormap_444, target_3, target_4)
and func_1(vicon_colormap_444, target_3, target_1)
and func_2(target_3, func, target_2)
and func_3(target_3)
and func_4(vicon_colormap_444, target_4)
and vicon_colormap_444.getType().hasName("unsigned char *")
and vicon_colormap_444.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
