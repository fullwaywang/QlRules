/**
 * @name libexif-6aa11df549114ebda520dde4cdaea2f9357b2c89-exif_data_load_data_content
 * @id cpp/libexif/6aa11df549114ebda520dde4cdaea2f9357b2c89/exif-data-load-data-content
 * @description libexif-6aa11df549114ebda520dde4cdaea2f9357b2c89-libexif/exif-data.c-exif_data_load_data_content CVE-2018-20030
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

/*predicate func_0(Parameter vrecursion_depth_366, BlockStmt target_12, VariableAccess target_0) {
		target_0.getTarget()=vrecursion_depth_366
		and target_0.getParent().(GTExpr).getLesserOperand().(Literal).getValue()="12"
		and target_0.getParent().(GTExpr).getParent().(IfStmt).getThen()=target_12
}

*/
/*predicate func_1(Parameter vrecursion_depth_366, Literal target_1) {
		target_1.getValue()="12"
		and not target_1.getValue()="170"
		and target_1.getParent().(GTExpr).getParent().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vrecursion_depth_366
}

*/
predicate func_2(Function func, StringLiteral target_2) {
		target_2.getValue()="Deep recursion detected!"
		and not target_2.getValue()="Deep/expensive recursion detected!"
		and target_2.getEnclosingFunction() = func
}

predicate func_3(Parameter vrecursion_depth_366, VariableAccess target_3) {
		target_3.getTarget()=vrecursion_depth_366
}

predicate func_4(Parameter vrecursion_depth_366, VariableAccess target_4) {
		target_4.getTarget()=vrecursion_depth_366
}

predicate func_5(Parameter vrecursion_depth_366, VariableAccess target_5) {
		target_5.getTarget()=vrecursion_depth_366
}

predicate func_6(Variable vn_369, RelationalOperation target_13) {
	exists(FunctionCall target_6 |
		target_6.getTarget().hasName("level_cost")
		and target_6.getArgument(0).(VariableAccess).getTarget()=vn_369
		and target_13.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_6.getArgument(0).(VariableAccess).getLocation()))
}

predicate func_7(Variable vn_369) {
	exists(FunctionCall target_7 |
		target_7.getTarget().hasName("level_cost")
		and target_7.getArgument(0).(VariableAccess).getTarget()=vn_369)
}

predicate func_8(Variable vn_369) {
	exists(FunctionCall target_8 |
		target_8.getTarget().hasName("level_cost")
		and target_8.getArgument(0).(VariableAccess).getTarget()=vn_369)
}

predicate func_12(BlockStmt target_12) {
		target_12.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("exif_log")
		and target_12.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="log"
		and target_12.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="priv"
		and target_12.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="ExifData"
		and target_12.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
}

predicate func_13(Variable vn_369, RelationalOperation target_13) {
		 (target_13 instanceof GTExpr or target_13 instanceof LTExpr)
		and target_13.getGreaterOperand().(VariableAccess).getTarget()=vn_369
}

from Function func, Parameter vrecursion_depth_366, Variable vn_369, StringLiteral target_2, VariableAccess target_3, VariableAccess target_4, VariableAccess target_5, BlockStmt target_12, RelationalOperation target_13
where
func_2(func, target_2)
and func_3(vrecursion_depth_366, target_3)
and func_4(vrecursion_depth_366, target_4)
and func_5(vrecursion_depth_366, target_5)
and not func_6(vn_369, target_13)
and not func_7(vn_369)
and not func_8(vn_369)
and func_12(target_12)
and func_13(vn_369, target_13)
and vrecursion_depth_366.getType().hasName("unsigned int")
and vn_369.getType().hasName("ExifShort")
and vrecursion_depth_366.getParentScope+() = func
and vn_369.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
