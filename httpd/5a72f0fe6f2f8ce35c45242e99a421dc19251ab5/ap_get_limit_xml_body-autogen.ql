/**
 * @name httpd-5a72f0fe6f2f8ce35c45242e99a421dc19251ab5-ap_get_limit_xml_body
 * @id cpp/httpd/5a72f0fe6f2f8ce35c45242e99a421dc19251ab5/ap-get-limit-xml-body
 * @description httpd-5a72f0fe6f2f8ce35c45242e99a421dc19251ab5-ap_get_limit_xml_body CVE-2022-22721
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vconf_3847, EqualityOperation target_1, ReturnStmt target_2, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="limit_xml_body"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconf_3847
		and target_0.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(ReturnStmt).getExpr().(SubExpr).getValue()="3074457345618258601"
		and (func.getEntryPoint().(BlockStmt).getStmt(3)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(3).getFollowingStmt()=target_0)
		and target_1.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vconf_3847, EqualityOperation target_1) {
		target_1.getAnOperand().(PointerFieldAccess).getTarget().getName()="limit_xml_body"
		and target_1.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconf_3847
		and target_1.getAnOperand().(UnaryMinusExpr).getValue()="-1"
}

predicate func_2(Variable vconf_3847, ReturnStmt target_2) {
		target_2.getExpr().(PointerFieldAccess).getTarget().getName()="limit_xml_body"
		and target_2.getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconf_3847
}

from Function func, Variable vconf_3847, EqualityOperation target_1, ReturnStmt target_2
where
not func_0(vconf_3847, target_1, target_2, func)
and func_1(vconf_3847, target_1)
and func_2(vconf_3847, target_2)
and vconf_3847.getType().hasName("core_dir_config *")
and vconf_3847.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
