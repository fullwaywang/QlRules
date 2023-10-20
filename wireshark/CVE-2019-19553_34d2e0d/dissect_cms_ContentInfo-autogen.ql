/**
 * @name wireshark-34d2e0d5318d0a7e9889498c721639e5cbf4ce45-dissect_cms_ContentInfo
 * @id cpp/wireshark/34d2e0d5318d0a7e9889498c721639e5cbf4ce45/dissect-cms-ContentInfo
 * @description wireshark-34d2e0d5318d0a7e9889498c721639e5cbf4ce45-epan/dissectors/packet-cms.c-dissect_cms_ContentInfo CVE-2019-19553
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("const char *")
		and target_0.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(3)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(3).getFollowingStmt()=target_0))
}

from Function func
where
not func_0(func)
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
