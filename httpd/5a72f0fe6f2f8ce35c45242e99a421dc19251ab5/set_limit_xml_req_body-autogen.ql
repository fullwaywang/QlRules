/**
 * @name httpd-5a72f0fe6f2f8ce35c45242e99a421dc19251ab5-set_limit_xml_req_body
 * @id cpp/httpd/5a72f0fe6f2f8ce35c45242e99a421dc19251ab5/set-limit-xml-req-body
 * @description httpd-5a72f0fe6f2f8ce35c45242e99a421dc19251ab5-set_limit_xml_req_body CVE-2022-22721
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vcmd_3755, Variable vconf_3758, RelationalOperation target_1, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="limit_xml_body"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconf_3758
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getValue()="3074457345618258601"
		and target_0.getThen().(ReturnStmt).getExpr().(FunctionCall).getTarget().hasName("apr_psprintf")
		and target_0.getThen().(ReturnStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="pool"
		and target_0.getThen().(ReturnStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcmd_3755
		and target_0.getThen().(ReturnStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="LimitXMLRequestBody must not exceed %lu"
		and target_0.getThen().(ReturnStmt).getExpr().(FunctionCall).getArgument(2).(SubExpr).getValue()="3074457345618258601"
		and (func.getEntryPoint().(BlockStmt).getStmt(3)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(3).getFollowingStmt()=target_0)
		and target_1.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vconf_3758, RelationalOperation target_1) {
		 (target_1 instanceof GTExpr or target_1 instanceof LTExpr)
		and target_1.getLesserOperand().(PointerFieldAccess).getTarget().getName()="limit_xml_body"
		and target_1.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconf_3758
		and target_1.getGreaterOperand().(Literal).getValue()="0"
}

from Function func, Parameter vcmd_3755, Variable vconf_3758, RelationalOperation target_1
where
not func_0(vcmd_3755, vconf_3758, target_1, func)
and func_1(vconf_3758, target_1)
and vcmd_3755.getType().hasName("cmd_parms *")
and vconf_3758.getType().hasName("core_dir_config *")
and vcmd_3755.getParentScope+() = func
and vconf_3758.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
