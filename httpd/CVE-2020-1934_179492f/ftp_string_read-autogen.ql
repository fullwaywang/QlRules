/**
 * @name httpd-179492ff35adbc239c2fcdcb3d6af117a11c105b-ftp_string_read
 * @id cpp/httpd/179492ff35adbc239c2fcdcb3d6af117a11c105b/ftp-string-read
 * @description httpd-179492ff35adbc239c2fcdcb3d6af117a11c105b-modules/proxy/mod_proxy_ftp.c-ftp_string_read CVE-2020-1934
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getType().hasName("apr_size_t *")
		and target_0.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(8)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(8).getFollowingStmt()=target_0))
}

predicate func_1(Variable vlen_228, RelationalOperation target_2, ExprStmt target_3) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignAddExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getType().hasName("apr_size_t *")
		and target_1.getExpr().(AssignAddExpr).getRValue().(VariableAccess).getTarget()=vlen_228
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
		and target_3.getExpr().(AssignPointerAddExpr).getRValue().(VariableAccess).getLocation().isBefore(target_1.getExpr().(AssignAddExpr).getRValue().(VariableAccess).getLocation()))
}

predicate func_2(Variable vlen_228, RelationalOperation target_2) {
		 (target_2 instanceof GTExpr or target_2 instanceof LTExpr)
		and target_2.getGreaterOperand().(VariableAccess).getTarget()=vlen_228
		and target_2.getLesserOperand().(Literal).getValue()="0"
}

predicate func_3(Variable vlen_228, ExprStmt target_3) {
		target_3.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget().getType().hasName("char *")
		and target_3.getExpr().(AssignPointerAddExpr).getRValue().(VariableAccess).getTarget()=vlen_228
}

from Function func, Variable vlen_228, RelationalOperation target_2, ExprStmt target_3
where
not func_0(func)
and not func_1(vlen_228, target_2, target_3)
and func_2(vlen_228, target_2)
and func_3(vlen_228, target_3)
and vlen_228.getType().hasName("apr_size_t")
and vlen_228.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
