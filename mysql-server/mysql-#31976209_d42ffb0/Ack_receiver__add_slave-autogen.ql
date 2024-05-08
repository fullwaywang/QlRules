/**
 * @name mysql-server-d42ffb0b7103011da185b9a2ed97c06c9bec957e-Ack_receiver__add_slave
 * @id cpp/mysql-server/d42ffb0b7103011da185b9a2ed97c06c9bec957e/ackreceiveraddslave
 * @description mysql-server-d42ffb0b7103011da185b9a2ed97c06c9bec957e-plugin/semisync/semisync_source_ack_receiver.cc-Ack_receiver__add_slave mysql-#31976209
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vslave_137, Function func, ExprStmt target_0) {
	exists(AssignExpr obj_0 | obj_0=target_0.getExpr() |
		exists(PointerFieldAccess obj_1 | obj_1=obj_0.getLValue() |
			exists(ValueFieldAccess obj_2 | obj_2=obj_1.getQualifier() |
				obj_2.getTarget().getName()="vio"
				and obj_2.getQualifier().(VariableAccess).getTarget()=vslave_137
			)
			and obj_1.getTarget().getName()="read_timeout"
		)
		and obj_0.getRValue().(Literal).getValue()="1"
	)
	and func.getEntryPoint().(BlockStmt).getAStmt()=target_0
}

from Function func, Variable vslave_137, ExprStmt target_0
where
func_0(vslave_137, func, target_0)
and vslave_137.getType().hasName("Slave")
and vslave_137.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
