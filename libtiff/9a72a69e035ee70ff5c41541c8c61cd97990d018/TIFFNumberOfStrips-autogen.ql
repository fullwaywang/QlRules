/**
 * @name libtiff-9a72a69e035ee70ff5c41541c8c61cd97990d018-TIFFNumberOfStrips
 * @id cpp/libtiff/9a72a69e035ee70ff5c41541c8c61cd97990d018/TIFFNumberOfStrips
 * @description libtiff-9a72a69e035ee70ff5c41541c8c61cd97990d018-libtiff/tif_strip.c-TIFFNumberOfStrips CVE-2016-10270
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vtd_63, Function func, IfStmt target_0) {
		target_0.getCondition().(PointerFieldAccess).getTarget().getName()="td_nstrips"
		and target_0.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtd_63
		and target_0.getThen().(ReturnStmt).getExpr().(PointerFieldAccess).getTarget().getName()="td_nstrips"
		and target_0.getThen().(ReturnStmt).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtd_63
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_0
}

from Function func, Variable vtd_63, IfStmt target_0
where
func_0(vtd_63, func, target_0)
and vtd_63.getType().hasName("TIFFDirectory *")
and vtd_63.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
