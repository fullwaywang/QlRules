/**
 * @name libzip-2217022b7d1142738656d891e00b3d2d9179b796-_zip_dirent_read
 * @id cpp/libzip/2217022b7d1142738656d891e00b3d2d9179b796/-zip-dirent-read
 * @description libzip-2217022b7d1142738656d891e00b3d2d9179b796-lib/zip_dirent.c-_zip_dirent_read CVE-2017-12858
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vbuffer_340, Variable vfrom_buffer_347, NotExpr target_2, ExprStmt target_3, NotExpr target_4, IfStmt target_0) {
		target_0.getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vfrom_buffer_347
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_zip_buffer_free")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbuffer_340
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_4.getOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(NotExpr).getOperand().(VariableAccess).getLocation())
}

/*predicate func_1(Parameter vbuffer_340, NotExpr target_5, ExprStmt target_3, ExprStmt target_1) {
		target_1.getExpr().(FunctionCall).getTarget().hasName("_zip_buffer_free")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbuffer_340
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

*/
predicate func_2(NotExpr target_2) {
		target_2.getOperand().(FunctionCall).getTarget().hasName("_zip_dirent_process_winzip_aes")
}

predicate func_3(Parameter vbuffer_340, ExprStmt target_3) {
		target_3.getExpr().(FunctionCall).getTarget().hasName("_zip_buffer_free")
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbuffer_340
}

predicate func_4(Variable vfrom_buffer_347, NotExpr target_4) {
		target_4.getOperand().(VariableAccess).getTarget()=vfrom_buffer_347
}

predicate func_5(Variable vfrom_buffer_347, NotExpr target_5) {
		target_5.getOperand().(VariableAccess).getTarget()=vfrom_buffer_347
}

from Function func, Parameter vbuffer_340, Variable vfrom_buffer_347, IfStmt target_0, NotExpr target_2, ExprStmt target_3, NotExpr target_4, NotExpr target_5
where
func_0(vbuffer_340, vfrom_buffer_347, target_2, target_3, target_4, target_0)
and func_2(target_2)
and func_3(vbuffer_340, target_3)
and func_4(vfrom_buffer_347, target_4)
and func_5(vfrom_buffer_347, target_5)
and vbuffer_340.getType().hasName("zip_buffer_t *")
and vfrom_buffer_347.getType().hasName("bool")
and vbuffer_340.getParentScope+() = func
and vfrom_buffer_347.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
