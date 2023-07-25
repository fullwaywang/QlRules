/**
 * @name libarchive-ba641f73f3d758d9032b3f0e5597a9c6e593a505-archive_read_format_zip_cleanup
 * @id cpp/libarchive/ba641f73f3d758d9032b3f0e5597a9c6e593a505/archive-read-format-zip-cleanup
 * @description libarchive-ba641f73f3d758d9032b3f0e5597a9c6e593a505-libarchive/archive_read_support_format_zip.c-archive_read_format_zip_cleanup CVE-2019-11463
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vzip_2744, AddressOfExpr target_1, IfStmt target_2, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(PointerFieldAccess).getTarget().getName()="zipx_lzma_valid"
		and target_0.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vzip_2744
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("lzma_end")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="zipx_lzma_stream"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vzip_2744
		and (func.getEntryPoint().(BlockStmt).getStmt(4)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(4).getFollowingStmt()=target_0)
		and target_1.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vzip_2744, AddressOfExpr target_1) {
		target_1.getOperand().(PointerFieldAccess).getTarget().getName()="stream"
		and target_1.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vzip_2744
}

predicate func_2(Variable vzip_2744, IfStmt target_2) {
		target_2.getCondition().(PointerFieldAccess).getTarget().getName()="bzstream_valid"
		and target_2.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vzip_2744
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("BZ2_bzDecompressEnd")
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="bzstream"
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vzip_2744
}

from Function func, Variable vzip_2744, AddressOfExpr target_1, IfStmt target_2
where
not func_0(vzip_2744, target_1, target_2, func)
and func_1(vzip_2744, target_1)
and func_2(vzip_2744, target_2)
and vzip_2744.getType().hasName("zip *")
and vzip_2744.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
