/**
 * @name mysql-server-b25312b2d666c0589dc688a2d83836d727cb41d0-mysql_audit_release
 * @id cpp/mysql-server/b25312b2d666c0589dc688a2d83836d727cb41d0/mysqlauditrelease
 * @description mysql-server-b25312b2d666c0589dc688a2d83836d727cb41d0-sql/sql_audit.cc-mysql_audit_release mysql-#34594035
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_3(Parameter vthd_1140, PointerFieldAccess target_3) {
	exists(FunctionCall obj_0 | obj_0=target_3.getParent() |
		exists(FunctionCall obj_1 | obj_1=obj_0.getParent() |
			exists(ExprStmt obj_2 | obj_2=obj_1.getParent() |
				exists(FunctionCall obj_3 | obj_3=obj_2.getExpr() |
					exists(FunctionCall obj_4 | obj_4=obj_3.getArgument(2) |
						exists(PointerFieldAccess obj_5 | obj_5=obj_4.getQualifier() |
							obj_5.getTarget().getName()="audit_class_plugins"
							and obj_5.getQualifier().(VariableAccess).getTarget()=vthd_1140
						)
						and obj_4.getTarget().hasName("size")
					)
					and obj_3.getTarget().hasName("plugin_unlock_list")
					and obj_3.getArgument(0).(Literal).getValue()="0"
					and obj_3.getArgument(1).(FunctionCall).getTarget().hasName("begin")
				)
			)
		)
	)
	and target_3.getTarget().getName()="audit_class_plugins"
	and target_3.getQualifier().(VariableAccess).getTarget()=vthd_1140
}

predicate func_4(Parameter vthd_1140, Function func, ExprStmt target_4) {
	exists(FunctionCall obj_0 | obj_0=target_4.getExpr() |
		exists(FunctionCall obj_1 | obj_1=obj_0.getArgument(1) |
			exists(PointerFieldAccess obj_2 | obj_2=obj_1.getQualifier() |
				obj_2.getTarget().getName()="audit_class_plugins"
				and obj_2.getQualifier().(VariableAccess).getTarget()=vthd_1140
			)
			and obj_1.getTarget().hasName("begin")
		)
		and exists(FunctionCall obj_3 | obj_3=obj_0.getArgument(2) |
			exists(PointerFieldAccess obj_4 | obj_4=obj_3.getQualifier() |
				obj_4.getTarget().getName()="audit_class_plugins"
				and obj_4.getQualifier().(VariableAccess).getTarget()=vthd_1140
			)
			and obj_3.getTarget().hasName("size")
		)
		and obj_0.getTarget().hasName("plugin_unlock_list")
		and obj_0.getArgument(0).(Literal).getValue()="0"
	)
	and func.getEntryPoint().(BlockStmt).getAStmt()=target_4
}

/*predicate func_5(Parameter vthd_1140, FunctionCall target_7, PointerFieldAccess target_5) {
	target_5.getTarget().getName()="audit_class_plugins"
	and target_5.getQualifier().(VariableAccess).getTarget()=vthd_1140
	and target_7.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_5.getQualifier().(VariableAccess).getLocation())
}

*/
predicate func_6(Parameter vthd_1140, FunctionCall target_6) {
	exists(PointerFieldAccess obj_0 | obj_0=target_6.getQualifier() |
		obj_0.getTarget().getName()="audit_class_plugins"
		and obj_0.getQualifier().(VariableAccess).getTarget()=vthd_1140
	)
	and target_6.getTarget().hasName("clear")
}

predicate func_7(Parameter vthd_1140, FunctionCall target_7) {
	exists(PointerFieldAccess obj_0 | obj_0=target_7.getQualifier() |
		obj_0.getTarget().getName()="audit_class_plugins"
		and obj_0.getQualifier().(VariableAccess).getTarget()=vthd_1140
	)
	and target_7.getTarget().hasName("begin")
}

from Function func, Parameter vthd_1140, PointerFieldAccess target_3, ExprStmt target_4, FunctionCall target_6, FunctionCall target_7
where
func_3(vthd_1140, target_3)
and func_4(vthd_1140, func, target_4)
and func_6(vthd_1140, target_6)
and func_7(vthd_1140, target_7)
and vthd_1140.getType().hasName("THD *")
and vthd_1140.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
