/**
 * @name libtiff-69818e2f2d246e6631ac2a2da692c3706b849c38-correct_orientation
 * @id cpp/libtiff/69818e2f2d246e6631ac2a2da692c3706b849c38/correct-orientation
 * @description libtiff-69818e2f2d246e6631ac2a2da692c3706b849c38-tools/tiffcrop.c-correct_orientation CVE-2023-25434
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_3(Parameter vimage_7230, VariableAccess target_3) {
		target_3.getTarget()=vimage_7230
		and target_3.getParent().(PointerFieldAccess).getParent().(AddressOfExpr).getParent().(FunctionCall).getParent().(IfStmt).getCondition().(FunctionCall).getTarget().hasName("rotateImage")
		and target_3.getParent().(PointerFieldAccess).getParent().(AddressOfExpr).getParent().(FunctionCall).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("uint16_t")
		and target_3.getParent().(PointerFieldAccess).getParent().(AddressOfExpr).getParent().(FunctionCall).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vimage_7230
		and target_3.getParent().(PointerFieldAccess).getParent().(AddressOfExpr).getParent().(FunctionCall).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="width"
		and target_3.getParent().(PointerFieldAccess).getParent().(AddressOfExpr).getParent().(FunctionCall).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="length"
		and target_3.getParent().(PointerFieldAccess).getParent().(AddressOfExpr).getParent().(FunctionCall).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_7230
		and target_3.getParent().(PointerFieldAccess).getParent().(AddressOfExpr).getParent().(FunctionCall).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(4).(VariableAccess).getTarget().getType().hasName("unsigned char **")
		and target_3.getParent().(PointerFieldAccess).getParent().(AddressOfExpr).getParent().(FunctionCall).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(5).(Literal).getValue()="0"
}

/*predicate func_4(Parameter vimage_7230, VariableAccess target_4) {
		target_4.getTarget()=vimage_7230
		and target_4.getParent().(PointerFieldAccess).getParent().(AddressOfExpr).getParent().(FunctionCall).getParent().(IfStmt).getCondition().(FunctionCall).getTarget().hasName("rotateImage")
		and target_4.getParent().(PointerFieldAccess).getParent().(AddressOfExpr).getParent().(FunctionCall).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("uint16_t")
		and target_4.getParent().(PointerFieldAccess).getParent().(AddressOfExpr).getParent().(FunctionCall).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vimage_7230
		and target_4.getParent().(PointerFieldAccess).getParent().(AddressOfExpr).getParent().(FunctionCall).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="width"
		and target_4.getParent().(PointerFieldAccess).getParent().(AddressOfExpr).getParent().(FunctionCall).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_7230
		and target_4.getParent().(PointerFieldAccess).getParent().(AddressOfExpr).getParent().(FunctionCall).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="length"
		and target_4.getParent().(PointerFieldAccess).getParent().(AddressOfExpr).getParent().(FunctionCall).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(4).(VariableAccess).getTarget().getType().hasName("unsigned char **")
		and target_4.getParent().(PointerFieldAccess).getParent().(AddressOfExpr).getParent().(FunctionCall).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(5).(Literal).getValue()="0"
}

*/
predicate func_5(Parameter vimage_7230, PointerFieldAccess target_5) {
		target_5.getTarget().getName()="width"
		and target_5.getQualifier().(VariableAccess).getTarget()=vimage_7230
}

predicate func_6(Parameter vimage_7230, PointerFieldAccess target_6) {
		target_6.getTarget().getName()="length"
		and target_6.getQualifier().(VariableAccess).getTarget()=vimage_7230
}

from Function func, Parameter vimage_7230, VariableAccess target_3, PointerFieldAccess target_5, PointerFieldAccess target_6
where
func_3(vimage_7230, target_3)
and func_5(vimage_7230, target_5)
and func_6(vimage_7230, target_6)
and vimage_7230.getType().hasName("image_data *")
and vimage_7230.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
