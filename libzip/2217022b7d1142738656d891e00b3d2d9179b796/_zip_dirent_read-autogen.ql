/**
 * @name libzip-2217022b7d1142738656d891e00b3d2d9179b796-_zip_dirent_read
 * @id cpp/libzip/2217022b7d1142738656d891e00b3d2d9179b796/-zip-dirent-read
 * @description libzip-2217022b7d1142738656d891e00b3d2d9179b796-_zip_dirent_read CVE-2017-12858
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vfrom_buffer_347, Parameter vbuffer_340, Parameter verror_340, Parameter vzde_340) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vfrom_buffer_347
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_zip_buffer_free")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbuffer_340
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("_zip_dirent_process_winzip_aes")
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vzde_340
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=verror_340)
}

from Function func, Variable vfrom_buffer_347, Parameter vbuffer_340, Parameter verror_340, Parameter vzde_340
where
func_0(vfrom_buffer_347, vbuffer_340, verror_340, vzde_340)
and vfrom_buffer_347.getType().hasName("bool")
and vbuffer_340.getType().hasName("zip_buffer_t *")
and verror_340.getType().hasName("zip_error_t *")
and vzde_340.getType().hasName("zip_dirent_t *")
and vfrom_buffer_347.getParentScope+() = func
and vbuffer_340.getParentScope+() = func
and verror_340.getParentScope+() = func
and vzde_340.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
