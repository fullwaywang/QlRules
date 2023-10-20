/**
 * @name openssl-4d8a88c134df634ba610ff8db1eb8478ac5fd345-ossl_rsaz_mod_exp_avx512_x2
 * @id cpp/openssl/4d8a88c134df634ba610ff8db1eb8478ac5fd345/ossl-rsaz-mod-exp-avx512-x2
 * @description openssl-4d8a88c134df634ba610ff8db1eb8478ac5fd345-ossl_rsaz_mod_exp_avx512_x2 CVE-2022-2274
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vfactor_size_151, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignDivExpr).getLValue().(VariableAccess).getTarget()=vfactor_size_151
		and target_0.getExpr().(AssignDivExpr).getRValue().(MulExpr).getValue()="64"
		and (func.getEntryPoint().(BlockStmt).getStmt(46)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(46).getFollowingStmt()=target_0))
}

predicate func_1(Parameter vm1_142, Parameter vfactor_size_151, Variable vstorage_172, Parameter vres1_139) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("bn_reduce_once_in_place")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vres1_139
		and target_1.getArgument(1).(Literal).getValue()="0"
		and target_1.getArgument(2).(VariableAccess).getTarget()=vm1_142
		and target_1.getArgument(3).(VariableAccess).getTarget()=vstorage_172
		and target_1.getArgument(4).(VariableAccess).getTarget()=vfactor_size_151)
}

from Function func, Parameter vm1_142, Parameter vfactor_size_151, Variable vstorage_172, Parameter vres1_139
where
not func_0(vfactor_size_151, func)
and vfactor_size_151.getType().hasName("int")
and func_1(vm1_142, vfactor_size_151, vstorage_172, vres1_139)
and vstorage_172.getType().hasName("unsigned long *")
and vres1_139.getType().hasName("unsigned long *")
and vm1_142.getParentScope+() = func
and vfactor_size_151.getParentScope+() = func
and vstorage_172.getParentScope+() = func
and vres1_139.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
