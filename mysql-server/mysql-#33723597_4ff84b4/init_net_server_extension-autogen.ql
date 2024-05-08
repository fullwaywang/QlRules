/**
 * @name mysql-server-4ff84b4470578773882d24bb1ec67c1a75b99eb9-init_net_server_extension
 * @id cpp/mysql-server/4ff84b4470578773882d24bb1ec67c1a75b99eb9/initnetserverextension
 * @description mysql-server-4ff84b4470578773882d24bb1ec67c1a75b99eb9-sql/conn_handler/init_net_server_extension.cc-init_net_server_extension mysql-#33723597
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vthd_115, ExprStmt target_1, ExprStmt target_2, FunctionCall target_3, Function func) {
exists(ExprStmt target_0 |
	exists(AssignExpr obj_0 | obj_0=target_0.getExpr() |
		exists(ValueFieldAccess obj_1 | obj_1=obj_0.getLValue() |
			exists(PointerFieldAccess obj_2 | obj_2=obj_1.getQualifier() |
				obj_2.getTarget().getName()="m_net_server_extension"
				and obj_2.getQualifier().(VariableAccess).getTarget()=vthd_115
			)
			and obj_1.getTarget().getName()="timeout_on_full_packet"
		)
		and obj_0.getRValue().(Literal).getValue()="0"
	)
	and func.getEntryPoint().(BlockStmt).getAStmt()=target_0
	and target_0.getLocation().isBefore(target_1.getLocation())
	and target_2.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
	and target_0.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getQualifier().(VariableAccess).getLocation())
)
}

predicate func_1(Parameter vthd_115, ExprStmt target_1) {
	exists(AssignExpr obj_0 | obj_0=target_1.getExpr() |
		exists(PointerFieldAccess obj_1 | obj_1=obj_0.getLValue() |
			exists(FunctionCall obj_2 | obj_2=obj_1.getQualifier() |
				exists(FunctionCall obj_3 | obj_3=obj_2.getQualifier() |
					obj_3.getTarget().hasName("get_protocol_classic")
					and obj_3.getQualifier().(VariableAccess).getTarget()=vthd_115
				)
				and obj_2.getTarget().hasName("get_net")
			)
			and obj_1.getTarget().getName()="extension"
		)
		and exists(AddressOfExpr obj_4 | obj_4=obj_0.getRValue() |
			exists(PointerFieldAccess obj_5 | obj_5=obj_4.getOperand() |
				obj_5.getTarget().getName()="m_net_server_extension"
				and obj_5.getQualifier().(VariableAccess).getTarget()=vthd_115
			)
		)
	)
}

predicate func_2(Parameter vthd_115, ExprStmt target_2) {
	exists(AssignExpr obj_0 | obj_0=target_2.getExpr() |
		exists(ValueFieldAccess obj_1 | obj_1=obj_0.getLValue() |
			exists(ValueFieldAccess obj_2 | obj_2=obj_1.getQualifier() |
				exists(PointerFieldAccess obj_3 | obj_3=obj_2.getQualifier() |
					obj_3.getTarget().getName()="m_net_server_extension"
					and obj_3.getQualifier().(VariableAccess).getTarget()=vthd_115
				)
				and obj_2.getTarget().getName()="compress_ctx"
			)
			and obj_1.getTarget().getName()="algorithm"
		)
	)
}

predicate func_3(Parameter vthd_115, FunctionCall target_3) {
	target_3.getTarget().hasName("get_protocol_classic")
	and target_3.getQualifier().(VariableAccess).getTarget()=vthd_115
}

from Function func, Parameter vthd_115, ExprStmt target_1, ExprStmt target_2, FunctionCall target_3
where
not func_0(vthd_115, target_1, target_2, target_3, func)
and func_1(vthd_115, target_1)
and func_2(vthd_115, target_2)
and func_3(vthd_115, target_3)
and vthd_115.getType().hasName("THD *")
and vthd_115.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
