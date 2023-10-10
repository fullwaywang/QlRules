/**
 * @name curl-c43127414d-Curl_conncache_init
 * @id cpp/curl/c43127414d/Curl-conncache-init
 * @description curl-c43127414d-lib/conncache.c-Curl_conncache_init CVE-2020-8231
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, SizeofTypeOperator target_0) {
		target_0.getType() instanceof LongType
		and target_0.getValue()="24"
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Parameter vtype_50, Variable vconnc_52, Function func, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="type"
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconnc_52
		and target_1.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vtype_50
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_1
}

predicate func_2(Variable vconnc_52, Function func, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="num_connections"
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconnc_52
		and target_2.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_2
}

from Function func, Parameter vtype_50, Variable vconnc_52, SizeofTypeOperator target_0, ExprStmt target_1, ExprStmt target_2
where
func_0(func, target_0)
and func_1(vtype_50, vconnc_52, func, target_1)
and func_2(vconnc_52, func, target_2)
and vtype_50.getType().hasName("conncachetype")
and vconnc_52.getType().hasName("conncache *")
and vtype_50.getParentScope+() = func
and vconnc_52.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
