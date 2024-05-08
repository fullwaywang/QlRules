/**
 * @name mysql-server-90bffcf20528189851a0142cf62cb84237e98790-innobase_init_files_
 * @id cpp/mysql-server/90bffcf20528189851a0142cf62cb84237e98790/innobaseinitfiles
 * @description mysql-server-90bffcf20528189851a0142cf62cb84237e98790-storage/innobase/srv/srv0srv.cc-innobase_init_files_ mysql-#33067891
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Literal target_0) {
	exists(FunctionCall obj_0 | obj_0=target_0.getParent() |
		exists(ExprStmt obj_1 | obj_1=obj_0.getParent() |
			exists(FunctionCall obj_2 | obj_2=obj_1.getExpr() |
				exists(ValueFieldAccess obj_3 | obj_3=obj_2.getArgument(0) |
					obj_3.getTarget().getName()="m_value"
					and obj_3.getQualifier().(VariableAccess).getTarget().getType().hasName("mysql_pfs_key_t")
				)
				and obj_2.getTarget().hasName("inline_mysql_mutex_init")
				and obj_2.getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("mysql_mutex_t")
				and obj_2.getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("native_mutexattr_t")
				and obj_2.getArgument(3).(StringLiteral).getValue()="/data/project/exp/build/cloned/mysql-server/storage/innobase/handler/ha_innodb.cc"
			)
		)
	)
	and target_0.getValue()="5427"
	and not target_0.getValue()="5424"
	and target_0.getEnclosingFunction() = func
}

predicate func_1(Function func, Literal target_1) {
	exists(FunctionCall obj_0 | obj_0=target_1.getParent() |
		exists(ExprStmt obj_1 | obj_1=obj_0.getParent() |
			exists(FunctionCall obj_2 | obj_2=obj_1.getExpr() |
				exists(ValueFieldAccess obj_3 | obj_3=obj_2.getArgument(0) |
					obj_3.getTarget().getName()="m_value"
					and obj_3.getQualifier().(VariableAccess).getTarget().getType().hasName("mysql_pfs_key_t")
				)
				and obj_2.getTarget().hasName("inline_mysql_mutex_init")
				and obj_2.getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("mysql_mutex_t")
				and obj_2.getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("native_mutexattr_t")
				and obj_2.getArgument(3).(StringLiteral).getValue()="/data/project/exp/build/cloned/mysql-server/storage/innobase/handler/ha_innodb.cc"
			)
		)
	)
	and target_1.getValue()="5429"
	and not target_1.getValue()="5426"
	and target_1.getEnclosingFunction() = func
}

predicate func_2(Function func, Literal target_2) {
	exists(FunctionCall obj_0 | obj_0=target_2.getParent() |
		exists(ExprStmt obj_1 | obj_1=obj_0.getParent() |
			exists(FunctionCall obj_2 | obj_2=obj_1.getExpr() |
				exists(ValueFieldAccess obj_3 | obj_3=obj_2.getArgument(0) |
					obj_3.getTarget().getName()="m_value"
					and obj_3.getQualifier().(VariableAccess).getTarget().getType().hasName("mysql_pfs_key_t")
				)
				and obj_2.getTarget().hasName("inline_mysql_cond_init")
				and obj_2.getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("mysql_cond_t")
				and obj_2.getArgument(2).(StringLiteral).getValue()="/data/project/exp/build/cloned/mysql-server/storage/innobase/handler/ha_innodb.cc"
			)
		)
	)
	and target_2.getValue()="5430"
	and not target_2.getValue()="5427"
	and target_2.getEnclosingFunction() = func
}

predicate func_3(Function func, Literal target_3) {
	exists(FunctionCall obj_0 | obj_0=target_3.getParent() |
		exists(ExprStmt obj_1 | obj_1=obj_0.getParent() |
			exists(FunctionCall obj_2 | obj_2=obj_1.getExpr() |
				exists(ValueFieldAccess obj_3 | obj_3=obj_2.getArgument(0) |
					obj_3.getTarget().getName()="m_value"
					and obj_3.getQualifier().(VariableAccess).getTarget().getType().hasName("mysql_pfs_key_t")
				)
				and obj_2.getTarget().hasName("inline_mysql_mutex_init")
				and obj_2.getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("mysql_mutex_t")
				and obj_2.getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("native_mutexattr_t")
				and obj_2.getArgument(3).(StringLiteral).getValue()="/data/project/exp/build/cloned/mysql-server/storage/innobase/handler/ha_innodb.cc"
			)
		)
	)
	and target_3.getValue()="5432"
	and not target_3.getValue()="5429"
	and target_3.getEnclosingFunction() = func
}

predicate func_4(Function func, Literal target_4) {
	exists(FunctionCall obj_0 | obj_0=target_4.getParent() |
		exists(ExprStmt obj_1 | obj_1=obj_0.getParent() |
			exists(FunctionCall obj_2 | obj_2=obj_1.getExpr() |
				exists(ValueFieldAccess obj_3 | obj_3=obj_2.getArgument(0) |
					obj_3.getTarget().getName()="m_value"
					and obj_3.getQualifier().(VariableAccess).getTarget().getType().hasName("mysql_pfs_key_t")
				)
				and obj_2.getTarget().hasName("inline_mysql_cond_init")
				and obj_2.getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("mysql_cond_t")
				and obj_2.getArgument(2).(StringLiteral).getValue()="/data/project/exp/build/cloned/mysql-server/storage/innobase/handler/ha_innodb.cc"
			)
		)
	)
	and target_4.getValue()="5433"
	and not target_4.getValue()="5430"
	and target_4.getEnclosingFunction() = func
}

predicate func_5(Variable vmaster_key_id_mutex, Function func, ExprStmt target_5) {
	exists(FunctionCall obj_0 | obj_0=target_5.getExpr() |
		obj_0.getTarget().hasName("mutex_init")
		and obj_0.getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vmaster_key_id_mutex
		and obj_0.getArgument(2).(StringLiteral).getValue()="/data/project/exp/build/cloned/mysql-server/storage/innobase/handler/ha_innodb.cc"
		and obj_0.getArgument(3).(Literal).getValue()="5418"
	)
	and func.getEntryPoint().(BlockStmt).getAStmt()=target_5
}

from Function func, Variable vmaster_key_id_mutex, Literal target_0, Literal target_1, Literal target_2, Literal target_3, Literal target_4, ExprStmt target_5
where
func_0(func, target_0)
and func_1(func, target_1)
and func_2(func, target_2)
and func_3(func, target_3)
and func_4(func, target_4)
and func_5(vmaster_key_id_mutex, func, target_5)
and vmaster_key_id_mutex.getType().hasName("ib_mutex_t")
and not vmaster_key_id_mutex.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
