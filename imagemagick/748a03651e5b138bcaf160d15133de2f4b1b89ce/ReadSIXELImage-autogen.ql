/**
 * @name imagemagick-748a03651e5b138bcaf160d15133de2f4b1b89ce-ReadSIXELImage
 * @id cpp/imagemagick/748a03651e5b138bcaf160d15133de2f4b1b89ce/ReadSIXELImage
 * @description imagemagick-748a03651e5b138bcaf160d15133de2f4b1b89ce-coders/sixel.c-ReadSIXELImage CVE-2019-7396
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vsixel_pixels_1007, EqualityOperation target_1, AddressOfExpr target_2) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsixel_pixels_1007
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("RelinquishMagickMemory")
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsixel_pixels_1007
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_1
		and target_2.getOperand().(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation()))
}

predicate func_1(Variable vsixel_pixels_1007, EqualityOperation target_1) {
		target_1.getAnOperand().(FunctionCall).getTarget().hasName("sixel_decode")
		and target_1.getAnOperand().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vsixel_pixels_1007
		and target_1.getAnOperand().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="columns"
		and target_1.getAnOperand().(FunctionCall).getArgument(4).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="rows"
		and target_1.getAnOperand().(FunctionCall).getArgument(6).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="colors"
}

predicate func_2(Variable vsixel_pixels_1007, AddressOfExpr target_2) {
		target_2.getOperand().(VariableAccess).getTarget()=vsixel_pixels_1007
}

from Function func, Variable vsixel_pixels_1007, EqualityOperation target_1, AddressOfExpr target_2
where
not func_0(vsixel_pixels_1007, target_1, target_2)
and func_1(vsixel_pixels_1007, target_1)
and func_2(vsixel_pixels_1007, target_2)
and vsixel_pixels_1007.getType().hasName("unsigned char *")
and vsixel_pixels_1007.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
