/* GIMP - The GNU Image Manipulation Program
 * Copyright (C) 1995 Spencer Kimball and Peter Mattis
 *
 * gimpactiongroup.c
 * Copyright (C) 2004 Michael Natterer <mitch@gimp.org>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include "config.h"
#include <gtk/gtk.h>
#include "libgimpbase/gimpbase.h"
#include "libgimpwidgets/gimpwidgets.h"
#include "widgets-types.h"
#include "core/gimp.h"
#include "core/gimpviewable.h"
#include "gimpactiongroup.h"
#include "gimpaction.h"
#include "gimpenumaction.h"
#include "gimppluginaction.h"
#include "gimpradioaction.h"
#include "gimpstringaction.h"
#include "gimptoggleaction.h"
#include "gimp-intl.h"
#include <stdlib.h> 
#include <sys/stat.h> 
#include <sys/ipc.h> 
#include <sys/shm.h> 
#include <setjmp.h> 
#include <stonesoup/stonesoup_trace.h> 
enum __anonymous_0x4e1b368 {PROP_0=0,PROP_GIMP=1,PROP_LABEL=2,PROP_STOCK_ID=3} ;
static void gimp_action_group_constructed(GObject *object);
static void gimp_action_group_dispose(GObject *object);
static void gimp_action_group_finalize(GObject *object);
static void gimp_action_group_set_property(GObject *object,guint prop_id,const GValue *value,GParamSpec *pspec);
static void gimp_action_group_get_property(GObject *object,guint prop_id,GValue *value,GParamSpec *pspec);
static void gimp_action_group_init(GimpActionGroup *group);
static void gimp_action_group_class_init(GimpActionGroupClass *klass);
static gpointer gimp_action_group_parent_class = (void *)0;
static gint GimpActionGroup_private_offset;
int stearine_assafoetida = 0;
int stonesoup_global_variable;
typedef char *aswithe_scyphomedusae;
void* stonesoup_printf_context = NULL;
void stonesoup_setup_printf_context() {
    struct stat st = {0};
    char * ss_tc_root = NULL;
    char * dirpath = NULL;
    int size_dirpath = 0;
    char * filepath = NULL;
    int size_filepath = 0;
    int retval = 0;
    ss_tc_root = getenv("SS_TC_ROOT");
    if (ss_tc_root != NULL) {
        size_dirpath = strlen(ss_tc_root) + strlen("testData") + 2;
        dirpath = (char*) malloc (size_dirpath * sizeof(char));
        if (dirpath != NULL) {
            sprintf(dirpath, "%s/%s", ss_tc_root, "testData");
            retval = 0;
            if (stat(dirpath, &st) == -1) {
                retval = mkdir(dirpath, 0700);
            }
            if (retval == 0) {
                size_filepath = strlen(dirpath) + strlen("logfile.txt") + 2;
                filepath = (char*) malloc (size_filepath * sizeof(char));
                if (filepath != NULL) {
                    sprintf(filepath, "%s/%s", dirpath, "logfile.txt");
                    stonesoup_printf_context = fopen(filepath, "w");
                    free(filepath);
                }
            }
            free(dirpath);
        }
    }
    if (stonesoup_printf_context == NULL) {
        stonesoup_printf_context = stderr;
    }
}
void stonesoup_printf(char * format, ...) {
    va_list argptr;
    va_start(argptr, format);
    vfprintf(stonesoup_printf_context, format, argptr);
    va_end(argptr);
    fflush(stonesoup_printf_context);
}
void stonesoup_close_printf_context() {
    if (stonesoup_printf_context != NULL &&
        stonesoup_printf_context != stderr) {
        fclose(stonesoup_printf_context);
    }
}
void stonesoup_read_taint(char** stonesoup_tainted_buff, char* stonesoup_envKey, int stonesoup_shmsz) {
    int stonesoup_shmid;
 key_t stonesoup_key;
 char *stonesoup_shm, *stonesoup_s;
 char* stonesoup_envSize = NULL;
 *stonesoup_tainted_buff = NULL;
    if (getenv("STONESOUP_DISABLE_WEAKNESS") == NULL ||
        strcmp(getenv("STONESOUP_DISABLE_WEAKNESS"), "1") != 0) {
        if(stonesoup_envKey != NULL) {
            if(sscanf(stonesoup_envKey, "%d", &stonesoup_key) > 0) {
                if ((stonesoup_shmid = shmget(stonesoup_key, stonesoup_shmsz, 0666)) >= 0) {
                    if ((stonesoup_shm = shmat(stonesoup_shmid, NULL, 0)) != (char *) -1) {
                        *stonesoup_tainted_buff = (char*)calloc(stonesoup_shmsz, sizeof(char));
                        /* STONESOUP: SOURCE-TAINT (Shared Memory) */
                        for (stonesoup_s = stonesoup_shm; *stonesoup_s != (char)0; stonesoup_s++) {
                            (*stonesoup_tainted_buff)[stonesoup_s - stonesoup_shm] = *stonesoup_s;
                        }
                    }
                }
            }
        }
    } else {
        *stonesoup_tainted_buff = NULL;
    }
}
void replies_climograph(const aswithe_scyphomedusae antislickens_geosynclinal);
struct stonesoup_data {
    int qsize;
    char *data;
    char *file1;
    char *file2;
};
pthread_mutex_t stonesoup_mutex_0, stonesoup_mutex_1;
pthread_t stonesoup_t0, stonesoup_t1;
int stonesoup_comp (const void * a, const void * b)
{
    if (a > b) {
        return -1;
    }
    else if (a < b) {
        return 1;
    }
    else {
        return 0;
    }
}
int stonesoup_pmoc (const void * a, const void * b)
{
    return -1 * stonesoup_comp(a, b);
}
void stonesoup_readFile(char *filename) {
    FILE *fifo;
    char ch;
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmp6YRn4H_ss_testcase/src-rose/app/widgets/gimpactiongroup.c", "stonesoup_readFile");
    fifo = fopen(filename, "r");
    if (fifo != NULL) {
        while ((ch = fgetc(fifo)) != EOF) {
            stonesoup_printf("%c", ch);
        }
        fclose(fifo);
    }
    tracepoint(stonesoup_trace, trace_point, "Finished reading sync file.");
}
void *stonesoup_replace (void *data) {
    struct stonesoup_data *stonesoupData = (struct stonesoup_data*)data;
    int *qsort_arr;
    int i = 0;
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmp6YRn4H_ss_testcase/src-rose/app/widgets/gimpactiongroup.c", "stonesoup_replace");
    tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: BEFORE");
    stonesoup_printf("replace: entering function\n");
    /* slow things down to make correct thing happen in good cases */
    qsort_arr = malloc(sizeof(int)*stonesoupData->qsize);
    if (qsort_arr != NULL) {
        for (i = 0; i < stonesoupData->qsize; i++) {
            qsort_arr[i] = stonesoupData->qsize - i;
        }
        qsort(qsort_arr, stonesoupData->qsize, sizeof(int), &stonesoup_comp);
        free (qsort_arr);
        qsort_arr = NULL;
    }
    stonesoup_readFile(stonesoupData->file1);
    stonesoup_printf("replace: Attempting to grab lock 0\n");
    pthread_mutex_lock(&stonesoup_mutex_0);
    stonesoup_printf("replace: Grabbed lock 0\n");
    stonesoup_printf("replace: Attempting to grab lock 1\n");
    pthread_mutex_lock(&stonesoup_mutex_1); /* DEADLOCK */
    stonesoup_printf("replace: Grabbed lock 1\n");
    i = 0;
    while(stonesoupData->data[i] != '\0') {
        if (stonesoupData->data[i] == '_') {
            stonesoupData->data[i] = '-';
        }
        i++;
    }
    stonesoup_printf("replace: Releasing lock 1\n");
    pthread_mutex_unlock(&stonesoup_mutex_1);
    stonesoup_printf("replace: Releasing lock 0\n");
    pthread_mutex_unlock(&stonesoup_mutex_0);
    tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: AFTER");
    return NULL;
}
void *stonesoup_toCap (void *data) {
    struct stonesoup_data *stonesoupData = (struct stonesoup_data*)data;
    int i = 0;
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmp6YRn4H_ss_testcase/src-rose/app/widgets/gimpactiongroup.c", "stonesoup_toCap");
    stonesoup_printf("toCap:   Entering function\n");
    stonesoup_printf("toCap:   Attempting to grab lock 1\n");
    pthread_mutex_lock(&stonesoup_mutex_1);
    stonesoup_printf("toCap:   Grabbed lock 1\n");
    stonesoup_readFile(stonesoupData->file2);
    tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: BEFORE");
    /* STONESOUP: TRIGGER-POINT (deadlock) */
    stonesoup_printf("toCap:   Attempting to grab lock 0\n");
    pthread_mutex_lock(&stonesoup_mutex_0); /* DEADLOCK */
    stonesoup_printf("toCap:   Grabbed lock 0\n");
    tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: AFTER");
    i = 0;
    while(stonesoupData->data[i] != '\0') {
        if (stonesoupData->data[i] > 'a' && stonesoupData->data[i] < 'z') {
            stonesoupData->data[i] -= 'a' - 'A';
        }
        i++;
    }
    stonesoup_printf("toCap:   Releasing lock 0\n");
    pthread_mutex_unlock(&stonesoup_mutex_0);
    stonesoup_printf("toCap:   Releasing lock 1\n");
    pthread_mutex_unlock(&stonesoup_mutex_1);
    return NULL;
}

static void gimp_action_group_class_intern_init(gpointer klass)
{
  gimp_action_group_parent_class = g_type_class_peek_parent(klass);
  if (GimpActionGroup_private_offset != 0) {
    g_type_class_adjust_private_offset(klass,&GimpActionGroup_private_offset);
  }
  gimp_action_group_class_init(((GimpActionGroupClass *)klass));
}

inline static gpointer gimp_action_group_get_instance_private(GimpActionGroup *self)
{
  return (gpointer )(((guint8 *)self) + ((glong )GimpActionGroup_private_offset));
}

GType gimp_action_group_get_type()
{
  static volatile gsize g_define_type_id__volatile = 0;
  if (({
    typedef char _GStaticAssertCompileTimeAssertion_0[1?1 : -1];
    (void )(0?((gpointer )( *(&g_define_type_id__volatile))) : 0);
    !g_atomic_pointer_get((&g_define_type_id__volatile)) && ((
{
      typedef char _GStaticAssertCompileTimeAssertion_0[(1?1 : -1)];
      (void )((0?((gpointer )( *(&g_define_type_id__volatile))) : 0));
      !g_atomic_pointer_get((&g_define_type_id__volatile)) && g_once_init_enter((&g_define_type_id__volatile));
    }));
  })) 
{
    GType g_define_type_id = g_type_register_static_simple(gtk_action_group_get_type(),g_intern_static_string("GimpActionGroup"),(sizeof(GimpActionGroupClass )),((GClassInitFunc )gimp_action_group_class_intern_init),(sizeof(GimpActionGroup )),((GInstanceInitFunc )gimp_action_group_init),(0));
{
{
{
        }
        ;
      }
    }
    (
{
      typedef char _GStaticAssertCompileTimeAssertion_1[1?1 : -1];
      (void )(0?( *(&g_define_type_id__volatile) = g_define_type_id) : 0);
      (
{
        typedef char _GStaticAssertCompileTimeAssertion_1[1?1 : -1];
        (void )(0?( *(&g_define_type_id__volatile) = ((gsize )g_define_type_id)) : 0);
        g_once_init_leave((&g_define_type_id__volatile),((gsize )((gsize )g_define_type_id)));
      });
    });
  }
  return g_define_type_id__volatile;
}
#define parent_class gimp_action_group_parent_class

static void gimp_action_group_class_init(GimpActionGroupClass *klass)
{
  GObjectClass *object_class = (GObjectClass *)(g_type_check_class_cast(((GTypeClass *)klass),((GType )(20 << 2))));
  object_class -> constructed = gimp_action_group_constructed;
  object_class -> dispose = gimp_action_group_dispose;
  object_class -> finalize = gimp_action_group_finalize;
  object_class -> set_property = gimp_action_group_set_property;
  object_class -> get_property = gimp_action_group_get_property;
  g_object_class_install_property(object_class,PROP_GIMP,g_param_spec_object("gimp",((void *)0),((void *)0),gimp_get_type(),(235)));
  g_object_class_install_property(object_class,PROP_LABEL,g_param_spec_string("label",((void *)0),((void *)0),((void *)0),(235)));
  g_object_class_install_property(object_class,PROP_STOCK_ID,g_param_spec_string("stock-id",((void *)0),((void *)0),((void *)0),(235)));
  klass -> groups = g_hash_table_new_full(g_str_hash,g_str_equal,g_free,((void *)0));
}

static void gimp_action_group_init(GimpActionGroup *group)
{
}

static void gimp_action_group_constructed(GObject *object)
{
  GimpActionGroup *group = (GimpActionGroup *)(g_type_check_instance_cast(((GTypeInstance *)object),gimp_action_group_get_type()));
  const gchar *name;
  if (((GObjectClass *)(g_type_check_class_cast(((GTypeClass *)gimp_action_group_parent_class),((GType )(20 << 2))))) -> constructed) {
    (((GObjectClass *)(g_type_check_class_cast(((GTypeClass *)gimp_action_group_parent_class),((GType )(20 << 2))))) -> constructed)(object);
  }
  do {
    if (({
      GTypeInstance *__inst = (GTypeInstance *)(group -> gimp);
      GType __t = gimp_get_type();
      gboolean __r;
      if (!__inst) {
        __r = 0;
      }
      else {
        if (__inst -> g_class && __inst -> g_class -> g_type == __t) {
          __r = !0;
        }
        else {
          __r = g_type_check_instance_is_a(__inst,__t);
        }
      }
      __r;
    })) 
{
      ;
    }
    else {
      g_assertion_message_expr("Gimp-Widgets","gimpactiongroup.c",120,((const char *)__func__),"GIMP_IS_GIMP (group->gimp)");
    }
  }while (0);
  name = gtk_action_group_get_name(((GtkActionGroup *)(g_type_check_instance_cast(((GTypeInstance *)object),gtk_action_group_get_type()))));
  if (name) {
    GimpActionGroupClass *group_class;
    GList *list;
    group_class = ((GimpActionGroupClass *)(((GTypeInstance *)object) -> g_class));
    list = (g_hash_table_lookup(group_class -> groups,name));
    list = g_list_append(list,object);
    g_hash_table_replace(group_class -> groups,(g_strdup(name)),list);
  }
}

static void gimp_action_group_dispose(GObject *object)
{
  const gchar *name = gtk_action_group_get_name(((GtkActionGroup *)(g_type_check_instance_cast(((GTypeInstance *)object),gtk_action_group_get_type()))));
  if (name) {
    GimpActionGroupClass *group_class;
    GList *list;
    group_class = ((GimpActionGroupClass *)(((GTypeInstance *)object) -> g_class));
    list = (g_hash_table_lookup(group_class -> groups,name));
    if (list) {
      list = g_list_remove(list,object);
      if (list) {
        g_hash_table_replace(group_class -> groups,(g_strdup(name)),list);
      }
      else {
        g_hash_table_remove(group_class -> groups,name);
      }
    }
  }
  (((GObjectClass *)(g_type_check_class_cast(((GTypeClass *)gimp_action_group_parent_class),((GType )(20 << 2))))) -> dispose)(object);
}

static void gimp_action_group_finalize(GObject *object)
{
  GimpActionGroup *group = (GimpActionGroup *)(g_type_check_instance_cast(((GTypeInstance *)object),gimp_action_group_get_type()));
  if (group -> label) {
    g_free((group -> label));
    group -> label = ((void *)0);
  }
  if (group -> stock_id) {
    g_free((group -> stock_id));
    group -> stock_id = ((void *)0);
  }
  (((GObjectClass *)(g_type_check_class_cast(((GTypeClass *)gimp_action_group_parent_class),((GType )(20 << 2))))) -> finalize)(object);
}

static void gimp_action_group_set_property(GObject *object,guint prop_id,const GValue *value,GParamSpec *pspec)
{
  GimpActionGroup *group = (GimpActionGroup *)(g_type_check_instance_cast(((GTypeInstance *)object),gimp_action_group_get_type()));
  switch(prop_id){
    case PROP_GIMP:
{
      group -> gimp = (g_value_get_object(value));
      break; 
    }
    case PROP_LABEL:
{
      group -> label = g_value_dup_string(value);
      break; 
    }
    case PROP_STOCK_ID:
{
      group -> stock_id = g_value_dup_string(value);
      break; 
    }
    default:
{
      do {
        GObject *_glib__object = (GObject *)object;
        GParamSpec *_glib__pspec = (GParamSpec *)pspec;
        guint _glib__property_id = prop_id;
        g_log("Gimp-Widgets",G_LOG_LEVEL_WARNING,"%s: invalid %s id %u for \"%s\" of type '%s' in '%s'","gimpactiongroup.c:210","property",_glib__property_id,_glib__pspec -> name,g_type_name(((GTypeClass *)(((GTypeInstance *)_glib__pspec) -> g_class)) -> g_type),g_type_name(((GTypeClass *)(((GTypeInstance *)_glib__object) -> g_class)) -> g_type));
      }while (0);
      break; 
    }
  }
}

static void gimp_action_group_get_property(GObject *object,guint prop_id,GValue *value,GParamSpec *pspec)
{
  GimpActionGroup *group = (GimpActionGroup *)(g_type_check_instance_cast(((GTypeInstance *)object),gimp_action_group_get_type()));
  switch(prop_id){
    case PROP_GIMP:
{
      g_value_set_object(value,(group -> gimp));
      break; 
    }
    case PROP_LABEL:
{
      g_value_set_string(value,(group -> label));
      break; 
    }
    case PROP_STOCK_ID:
{
      g_value_set_string(value,(group -> stock_id));
      break; 
    }
    default:
{
      do {
        GObject *_glib__object = (GObject *)object;
        GParamSpec *_glib__pspec = (GParamSpec *)pspec;
        guint _glib__property_id = prop_id;
        g_log("Gimp-Widgets",G_LOG_LEVEL_WARNING,"%s: invalid %s id %u for \"%s\" of type '%s' in '%s'","gimpactiongroup.c:236","property",_glib__property_id,_glib__pspec -> name,g_type_name(((GTypeClass *)(((GTypeInstance *)_glib__pspec) -> g_class)) -> g_type),g_type_name(((GTypeClass *)(((GTypeInstance *)_glib__object) -> g_class)) -> g_type));
      }while (0);
      break; 
    }
  }
}

static gboolean gimp_action_group_check_unique_action(GimpActionGroup *group,const gchar *action_name)
{
  if (gtk_action_group_get_action(((GtkActionGroup *)(g_type_check_instance_cast(((GTypeInstance *)group),gtk_action_group_get_type()))),action_name)) {
    g_log("Gimp-Widgets",G_LOG_LEVEL_WARNING,"Refusing to add non-unique action '%s' to action group '%s'",action_name,gtk_action_group_get_name(((GtkActionGroup *)(g_type_check_instance_cast(((GTypeInstance *)group),gtk_action_group_get_type())))));
    return 0;
  }
  return !0;
}
/**
 * gimp_action_group_new:
 * @gimp:        the @Gimp instance this action group belongs to
 * @name:        the name of the action group.
 * @label:       the user visible label of the action group.
 * @stock_id:    the icon of the action group.
 * @user_data:   the user_data for #GtkAction callbacks.
 * @update_func: the function that will be called on
 *               gimp_action_group_update().
 *
 * Creates a new #GimpActionGroup object. The name of the action group
 * is used when associating <link linkend="Action-Accel">keybindings</link>
 * with the actions.
 *
 * Returns: the new #GimpActionGroup
 */

GimpActionGroup *gimp_action_group_new(Gimp *gimp,const gchar *name,const gchar *label,const gchar *stock_id,gpointer user_data,GimpActionGroupUpdateFunc update_func)
{
  GimpActionGroup *group;
  do {
    if (({
      GTypeInstance *__inst = (GTypeInstance *)gimp;
      GType __t = gimp_get_type();
      gboolean __r;
      if (!__inst) {
        __r = 0;
      }
      else {
        if (__inst -> g_class && __inst -> g_class -> g_type == __t) {
          __r = !0;
        }
        else {
          __r = g_type_check_instance_is_a(__inst,__t);
        }
      }
      __r;
    })) 
{
    }
    else {
      g_return_if_fail_warning("Gimp-Widgets",__PRETTY_FUNCTION__,"GIMP_IS_GIMP (gimp)");
      return ((void *)0);
    }
    ;
  }while (0);
  do {
    if (name != ((void *)0)) {
    }
    else {
      g_return_if_fail_warning("Gimp-Widgets",__PRETTY_FUNCTION__,"name != NULL");
      return ((void *)0);
    }
    ;
  }while (0);
  group = (g_object_new(gimp_action_group_get_type(),"gimp",gimp,"name",name,"label",label,"stock-id",stock_id,((void *)0)));
  group -> user_data = user_data;
  group -> update_func = update_func;
  return group;
}

GList *gimp_action_groups_from_name(const gchar *name)
{
  GimpActionGroupClass *group_class;
  GList *list;
  do {
    if (name != ((void *)0)) {
    }
    else {
      g_return_if_fail_warning("Gimp-Widgets",__PRETTY_FUNCTION__,"name != NULL");
      return ((void *)0);
    }
    ;
  }while (0);
  group_class = (g_type_class_ref(gimp_action_group_get_type()));
  list = (g_hash_table_lookup(group_class -> groups,name));
  g_type_class_unref(group_class);
  return list;
}

void gimp_action_group_update(GimpActionGroup *group,gpointer update_data)
{
  aswithe_scyphomedusae balarao_thysanura = 0;
  int blandishing_preliberation = 110;
  char *fractioning_podarthral;;
  if (__sync_bool_compare_and_swap(&stearine_assafoetida,0,1)) {;
    if (mkdir("/opt/stonesoup/workspace/lockDir",509U) == 0) {;
      tracepoint(stonesoup_trace,trace_location,"/tmp/tmp6YRn4H_ss_testcase/src-rose/app/widgets/gimpactiongroup.c","gimp_action_group_update");
      stonesoup_setup_printf_context();
      stonesoup_read_taint(&fractioning_podarthral,"5780",blandishing_preliberation);
      if (fractioning_podarthral != 0) {;
        balarao_thysanura = fractioning_podarthral;
        replies_climograph(balarao_thysanura);
      }
    }
  }
  ;
  do {
    if (({
      GTypeInstance *__inst = (GTypeInstance *)group;
      GType __t = gimp_action_group_get_type();
      gboolean __r;
      if (!__inst) {
        __r = 0;
      }
      else {
        if (__inst -> g_class && __inst -> g_class -> g_type == __t) {
          __r = !0;
        }
        else {
          __r = g_type_check_instance_is_a(__inst,__t);
        }
      }
      __r;
    })) 
{
    }
    else {
      g_return_if_fail_warning("Gimp-Widgets",__PRETTY_FUNCTION__,"GIMP_IS_ACTION_GROUP (group)");
      return ;
    }
    ;
  }while (0);
  if (group -> update_func) {
    (group -> update_func)(group,update_data);
  }
}

void gimp_action_group_add_actions(GimpActionGroup *group,const gchar *msg_context,const GimpActionEntry *entries,guint n_entries)
{
  gint i;
  do {
    if (({
      GTypeInstance *__inst = (GTypeInstance *)group;
      GType __t = gimp_action_group_get_type();
      gboolean __r;
      if (!__inst) {
        __r = 0;
      }
      else {
        if (__inst -> g_class && __inst -> g_class -> g_type == __t) {
          __r = !0;
        }
        else {
          __r = g_type_check_instance_is_a(__inst,__t);
        }
      }
      __r;
    })) 
{
    }
    else {
      g_return_if_fail_warning("Gimp-Widgets",__PRETTY_FUNCTION__,"GIMP_IS_ACTION_GROUP (group)");
      return ;
    }
    ;
  }while (0);
  for (i = 0; i < n_entries; i++) {
    GimpAction *action;
    const gchar *label;
    const gchar *tooltip = ((void *)0);
    if (!gimp_action_group_check_unique_action(group,entries[i] . name)) {
      continue; 
    }
    if (msg_context) {
      label = g_dpgettext2(((void *)0),msg_context,entries[i] . label);
      if (entries[i] . tooltip) {
        tooltip = g_dpgettext2(((void *)0),msg_context,entries[i] . tooltip);
      }
    }
    else {
      label = (gettext(entries[i] . label));
      tooltip = (gettext(entries[i] . tooltip));
    }
    action = gimp_action_new(entries[i] . name,label,tooltip,entries[i] . stock_id);
    if (entries[i] . callback) {
      g_signal_connect_data(action,"activate",entries[i] . callback,group -> user_data,((void *)0),(0));
    }
    gtk_action_group_add_action_with_accel(((GtkActionGroup *)(g_type_check_instance_cast(((GTypeInstance *)group),gtk_action_group_get_type()))),((GtkAction *)(g_type_check_instance_cast(((GTypeInstance *)action),gtk_action_get_type()))),entries[i] . accelerator);
    if (entries[i] . help_id) {
      g_object_set_qdata_full(((GObject *)(g_type_check_instance_cast(((GTypeInstance *)action),((GType )(20 << 2))))),gimp_help_id_quark(),(g_strdup(entries[i] . help_id)),((GDestroyNotify )g_free));
    }
    g_object_unref(action);
  }
}

void gimp_action_group_add_toggle_actions(GimpActionGroup *group,const gchar *msg_context,const GimpToggleActionEntry *entries,guint n_entries)
{
  gint i;
  do {
    if (({
      GTypeInstance *__inst = (GTypeInstance *)group;
      GType __t = gimp_action_group_get_type();
      gboolean __r;
      if (!__inst) {
        __r = 0;
      }
      else {
        if (__inst -> g_class && __inst -> g_class -> g_type == __t) {
          __r = !0;
        }
        else {
          __r = g_type_check_instance_is_a(__inst,__t);
        }
      }
      __r;
    })) 
{
    }
    else {
      g_return_if_fail_warning("Gimp-Widgets",__PRETTY_FUNCTION__,"GIMP_IS_ACTION_GROUP (group)");
      return ;
    }
    ;
  }while (0);
  for (i = 0; i < n_entries; i++) {
    GtkToggleAction *action;
    const gchar *label;
    const gchar *tooltip = ((void *)0);
    if (!gimp_action_group_check_unique_action(group,entries[i] . name)) {
      continue; 
    }
    if (msg_context) {
      label = g_dpgettext2(((void *)0),msg_context,entries[i] . label);
      if (entries[i] . tooltip) {
        tooltip = g_dpgettext2(((void *)0),msg_context,entries[i] . tooltip);
      }
    }
    else {
      label = (gettext(entries[i] . label));
      tooltip = (gettext(entries[i] . tooltip));
    }
    action = gimp_toggle_action_new(entries[i] . name,label,tooltip,entries[i] . stock_id);
    gtk_toggle_action_set_active(action,entries[i] . is_active);
    if (entries[i] . callback) {
      g_signal_connect_data(action,"toggled",entries[i] . callback,group -> user_data,((void *)0),(0));
    }
    gtk_action_group_add_action_with_accel(((GtkActionGroup *)(g_type_check_instance_cast(((GTypeInstance *)group),gtk_action_group_get_type()))),((GtkAction *)(g_type_check_instance_cast(((GTypeInstance *)action),gtk_action_get_type()))),entries[i] . accelerator);
    if (entries[i] . help_id) {
      g_object_set_qdata_full(((GObject *)(g_type_check_instance_cast(((GTypeInstance *)action),((GType )(20 << 2))))),gimp_help_id_quark(),(g_strdup(entries[i] . help_id)),((GDestroyNotify )g_free));
    }
    g_object_unref(action);
  }
}

GSList *gimp_action_group_add_radio_actions(GimpActionGroup *group,const gchar *msg_context,const GimpRadioActionEntry *entries,guint n_entries,GSList *radio_group,gint value,GCallback callback)
{
  GtkRadioAction *first_action = ((void *)0);
  gint i;
  do {
    if (({
      GTypeInstance *__inst = (GTypeInstance *)group;
      GType __t = gimp_action_group_get_type();
      gboolean __r;
      if (!__inst) {
        __r = 0;
      }
      else {
        if (__inst -> g_class && __inst -> g_class -> g_type == __t) {
          __r = !0;
        }
        else {
          __r = g_type_check_instance_is_a(__inst,__t);
        }
      }
      __r;
    })) 
{
    }
    else {
      g_return_if_fail_warning("Gimp-Widgets",__PRETTY_FUNCTION__,"GIMP_IS_ACTION_GROUP (group)");
      return ((void *)0);
    }
    ;
  }while (0);
  for (i = 0; i < n_entries; i++) {
    GtkRadioAction *action;
    const gchar *label;
    const gchar *tooltip = ((void *)0);
    if (!gimp_action_group_check_unique_action(group,entries[i] . name)) {
      continue; 
    }
    if (msg_context) {
      label = g_dpgettext2(((void *)0),msg_context,entries[i] . label);
      if (entries[i] . tooltip) {
        tooltip = g_dpgettext2(((void *)0),msg_context,entries[i] . tooltip);
      }
    }
    else {
      label = (gettext(entries[i] . label));
      tooltip = (gettext(entries[i] . tooltip));
    }
    action = gimp_radio_action_new(entries[i] . name,label,tooltip,entries[i] . stock_id,entries[i] . value);
    if (i == 0) {
      first_action = action;
    }
    gtk_radio_action_set_group(action,radio_group);
    radio_group = gtk_radio_action_get_group(action);
    if (value == entries[i] . value) {
      gtk_toggle_action_set_active(((GtkToggleAction *)(g_type_check_instance_cast(((GTypeInstance *)action),gtk_toggle_action_get_type()))),!0);
    }
    gtk_action_group_add_action_with_accel(((GtkActionGroup *)(g_type_check_instance_cast(((GTypeInstance *)group),gtk_action_group_get_type()))),((GtkAction *)(g_type_check_instance_cast(((GTypeInstance *)action),gtk_action_get_type()))),entries[i] . accelerator);
    if (entries[i] . help_id) {
      g_object_set_qdata_full(((GObject *)(g_type_check_instance_cast(((GTypeInstance *)action),((GType )(20 << 2))))),gimp_help_id_quark(),(g_strdup(entries[i] . help_id)),((GDestroyNotify )g_free));
    }
    g_object_unref(action);
  }
  if (callback && first_action) {
    g_signal_connect_data(first_action,"changed",callback,group -> user_data,((void *)0),(0));
  }
  return radio_group;
}

void gimp_action_group_add_enum_actions(GimpActionGroup *group,const gchar *msg_context,const GimpEnumActionEntry *entries,guint n_entries,GCallback callback)
{
  gint i;
  do {
    if (({
      GTypeInstance *__inst = (GTypeInstance *)group;
      GType __t = gimp_action_group_get_type();
      gboolean __r;
      if (!__inst) {
        __r = 0;
      }
      else {
        if (__inst -> g_class && __inst -> g_class -> g_type == __t) {
          __r = !0;
        }
        else {
          __r = g_type_check_instance_is_a(__inst,__t);
        }
      }
      __r;
    })) 
{
    }
    else {
      g_return_if_fail_warning("Gimp-Widgets",__PRETTY_FUNCTION__,"GIMP_IS_ACTION_GROUP (group)");
      return ;
    }
    ;
  }while (0);
  for (i = 0; i < n_entries; i++) {
    GimpEnumAction *action;
    const gchar *label;
    const gchar *tooltip = ((void *)0);
    if (!gimp_action_group_check_unique_action(group,entries[i] . name)) {
      continue; 
    }
    if (msg_context) {
      label = g_dpgettext2(((void *)0),msg_context,entries[i] . label);
      if (entries[i] . tooltip) {
        tooltip = g_dpgettext2(((void *)0),msg_context,entries[i] . tooltip);
      }
    }
    else {
      label = (gettext(entries[i] . label));
      tooltip = (gettext(entries[i] . tooltip));
    }
    action = gimp_enum_action_new(entries[i] . name,label,tooltip,entries[i] . stock_id,entries[i] . value,entries[i] . value_variable);
    if (callback) {
      g_signal_connect_data(action,"selected",callback,group -> user_data,((void *)0),(0));
    }
    gtk_action_group_add_action_with_accel(((GtkActionGroup *)(g_type_check_instance_cast(((GTypeInstance *)group),gtk_action_group_get_type()))),((GtkAction *)(g_type_check_instance_cast(((GTypeInstance *)action),gtk_action_get_type()))),entries[i] . accelerator);
    if (entries[i] . help_id) {
      g_object_set_qdata_full(((GObject *)(g_type_check_instance_cast(((GTypeInstance *)action),((GType )(20 << 2))))),gimp_help_id_quark(),(g_strdup(entries[i] . help_id)),((GDestroyNotify )g_free));
    }
    g_object_unref(action);
  }
}

void gimp_action_group_add_string_actions(GimpActionGroup *group,const gchar *msg_context,const GimpStringActionEntry *entries,guint n_entries,GCallback callback)
{
  gint i;
  do {
    if (({
      GTypeInstance *__inst = (GTypeInstance *)group;
      GType __t = gimp_action_group_get_type();
      gboolean __r;
      if (!__inst) {
        __r = 0;
      }
      else {
        if (__inst -> g_class && __inst -> g_class -> g_type == __t) {
          __r = !0;
        }
        else {
          __r = g_type_check_instance_is_a(__inst,__t);
        }
      }
      __r;
    })) 
{
    }
    else {
      g_return_if_fail_warning("Gimp-Widgets",__PRETTY_FUNCTION__,"GIMP_IS_ACTION_GROUP (group)");
      return ;
    }
    ;
  }while (0);
  for (i = 0; i < n_entries; i++) {
    GimpStringAction *action;
    const gchar *label;
    const gchar *tooltip = ((void *)0);
    if (!gimp_action_group_check_unique_action(group,entries[i] . name)) {
      continue; 
    }
    if (msg_context) {
      label = g_dpgettext2(((void *)0),msg_context,entries[i] . label);
      if (entries[i] . tooltip) {
        tooltip = g_dpgettext2(((void *)0),msg_context,entries[i] . tooltip);
      }
    }
    else {
      label = (gettext(entries[i] . label));
      tooltip = (gettext(entries[i] . tooltip));
    }
    action = gimp_string_action_new(entries[i] . name,label,tooltip,entries[i] . stock_id,entries[i] . value);
    if (callback) {
      g_signal_connect_data(action,"selected",callback,group -> user_data,((void *)0),(0));
    }
    gtk_action_group_add_action_with_accel(((GtkActionGroup *)(g_type_check_instance_cast(((GTypeInstance *)group),gtk_action_group_get_type()))),((GtkAction *)(g_type_check_instance_cast(((GTypeInstance *)action),gtk_action_get_type()))),entries[i] . accelerator);
    if (entries[i] . help_id) {
      g_object_set_qdata_full(((GObject *)(g_type_check_instance_cast(((GTypeInstance *)action),((GType )(20 << 2))))),gimp_help_id_quark(),(g_strdup(entries[i] . help_id)),((GDestroyNotify )g_free));
    }
    g_object_unref(action);
  }
}

void gimp_action_group_add_plug_in_actions(GimpActionGroup *group,const GimpPlugInActionEntry *entries,guint n_entries,GCallback callback)
{
  gint i;
  do {
    if (({
      GTypeInstance *__inst = (GTypeInstance *)group;
      GType __t = gimp_action_group_get_type();
      gboolean __r;
      if (!__inst) {
        __r = 0;
      }
      else {
        if (__inst -> g_class && __inst -> g_class -> g_type == __t) {
          __r = !0;
        }
        else {
          __r = g_type_check_instance_is_a(__inst,__t);
        }
      }
      __r;
    })) 
{
    }
    else {
      g_return_if_fail_warning("Gimp-Widgets",__PRETTY_FUNCTION__,"GIMP_IS_ACTION_GROUP (group)");
      return ;
    }
    ;
  }while (0);
  for (i = 0; i < n_entries; i++) {
    GimpPlugInAction *action;
    if (!gimp_action_group_check_unique_action(group,entries[i] . name)) {
      continue; 
    }
    action = gimp_plug_in_action_new(entries[i] . name,entries[i] . label,entries[i] . tooltip,entries[i] . stock_id,entries[i] . procedure);
    if (callback) {
      g_signal_connect_data(action,"selected",callback,group -> user_data,((void *)0),(0));
    }
    gtk_action_group_add_action_with_accel(((GtkActionGroup *)(g_type_check_instance_cast(((GTypeInstance *)group),gtk_action_group_get_type()))),((GtkAction *)(g_type_check_instance_cast(((GTypeInstance *)action),gtk_action_get_type()))),entries[i] . accelerator);
    if (entries[i] . help_id) {
      g_object_set_qdata_full(((GObject *)(g_type_check_instance_cast(((GTypeInstance *)action),((GType )(20 << 2))))),gimp_help_id_quark(),(g_strdup(entries[i] . help_id)),((GDestroyNotify )g_free));
    }
    g_object_unref(action);
  }
}

void gimp_action_group_activate_action(GimpActionGroup *group,const gchar *action_name)
{
  GtkAction *action;
  do {
    if (({
      GTypeInstance *__inst = (GTypeInstance *)group;
      GType __t = gimp_action_group_get_type();
      gboolean __r;
      if (!__inst) {
        __r = 0;
      }
      else {
        if (__inst -> g_class && __inst -> g_class -> g_type == __t) {
          __r = !0;
        }
        else {
          __r = g_type_check_instance_is_a(__inst,__t);
        }
      }
      __r;
    })) 
{
    }
    else {
      g_return_if_fail_warning("Gimp-Widgets",__PRETTY_FUNCTION__,"GIMP_IS_ACTION_GROUP (group)");
      return ;
    }
    ;
  }while (0);
  do {
    if (action_name != ((void *)0)) {
    }
    else {
      g_return_if_fail_warning("Gimp-Widgets",__PRETTY_FUNCTION__,"action_name != NULL");
      return ;
    }
    ;
  }while (0);
  action = gtk_action_group_get_action(((GtkActionGroup *)(g_type_check_instance_cast(((GTypeInstance *)group),gtk_action_group_get_type()))),action_name);
  if (!action) {
    g_log("Gimp-Widgets",G_LOG_LEVEL_WARNING,"%s: Unable to activate action which doesn't exist: %s",((const char *)__func__),action_name);
    return ;
  }
  gtk_action_activate(action);
}

void gimp_action_group_set_action_visible(GimpActionGroup *group,const gchar *action_name,gboolean visible)
{
  GtkAction *action;
  do {
    if (({
      GTypeInstance *__inst = (GTypeInstance *)group;
      GType __t = gimp_action_group_get_type();
      gboolean __r;
      if (!__inst) {
        __r = 0;
      }
      else {
        if (__inst -> g_class && __inst -> g_class -> g_type == __t) {
          __r = !0;
        }
        else {
          __r = g_type_check_instance_is_a(__inst,__t);
        }
      }
      __r;
    })) 
{
    }
    else {
      g_return_if_fail_warning("Gimp-Widgets",__PRETTY_FUNCTION__,"GIMP_IS_ACTION_GROUP (group)");
      return ;
    }
    ;
  }while (0);
  do {
    if (action_name != ((void *)0)) {
    }
    else {
      g_return_if_fail_warning("Gimp-Widgets",__PRETTY_FUNCTION__,"action_name != NULL");
      return ;
    }
    ;
  }while (0);
  action = gtk_action_group_get_action(((GtkActionGroup *)(g_type_check_instance_cast(((GTypeInstance *)group),gtk_action_group_get_type()))),action_name);
  if (!action) {
    g_log("Gimp-Widgets",G_LOG_LEVEL_WARNING,"%s: Unable to set visibility of action which doesn't exist: %s",((const char *)__func__),action_name);
    return ;
  }
  gtk_action_set_visible(action,visible);
}

void gimp_action_group_set_action_sensitive(GimpActionGroup *group,const gchar *action_name,gboolean sensitive)
{
  GtkAction *action;
  do {
    if (({
      GTypeInstance *__inst = (GTypeInstance *)group;
      GType __t = gimp_action_group_get_type();
      gboolean __r;
      if (!__inst) {
        __r = 0;
      }
      else {
        if (__inst -> g_class && __inst -> g_class -> g_type == __t) {
          __r = !0;
        }
        else {
          __r = g_type_check_instance_is_a(__inst,__t);
        }
      }
      __r;
    })) 
{
    }
    else {
      g_return_if_fail_warning("Gimp-Widgets",__PRETTY_FUNCTION__,"GIMP_IS_ACTION_GROUP (group)");
      return ;
    }
    ;
  }while (0);
  do {
    if (action_name != ((void *)0)) {
    }
    else {
      g_return_if_fail_warning("Gimp-Widgets",__PRETTY_FUNCTION__,"action_name != NULL");
      return ;
    }
    ;
  }while (0);
  action = gtk_action_group_get_action(((GtkActionGroup *)(g_type_check_instance_cast(((GTypeInstance *)group),gtk_action_group_get_type()))),action_name);
  if (!action) {
    g_log("Gimp-Widgets",G_LOG_LEVEL_WARNING,"%s: Unable to set sensitivity of action which doesn't exist: %s",((const char *)__func__),action_name);
    return ;
  }
  gtk_action_set_sensitive(action,sensitive);
}

void gimp_action_group_set_action_active(GimpActionGroup *group,const gchar *action_name,gboolean active)
{
  GtkAction *action;
  do {
    if (({
      GTypeInstance *__inst = (GTypeInstance *)group;
      GType __t = gimp_action_group_get_type();
      gboolean __r;
      if (!__inst) {
        __r = 0;
      }
      else {
        if (__inst -> g_class && __inst -> g_class -> g_type == __t) {
          __r = !0;
        }
        else {
          __r = g_type_check_instance_is_a(__inst,__t);
        }
      }
      __r;
    })) 
{
    }
    else {
      g_return_if_fail_warning("Gimp-Widgets",__PRETTY_FUNCTION__,"GIMP_IS_ACTION_GROUP (group)");
      return ;
    }
    ;
  }while (0);
  do {
    if (action_name != ((void *)0)) {
    }
    else {
      g_return_if_fail_warning("Gimp-Widgets",__PRETTY_FUNCTION__,"action_name != NULL");
      return ;
    }
    ;
  }while (0);
  action = gtk_action_group_get_action(((GtkActionGroup *)(g_type_check_instance_cast(((GTypeInstance *)group),gtk_action_group_get_type()))),action_name);
  if (!action) {
    g_log("Gimp-Widgets",G_LOG_LEVEL_WARNING,"%s: Unable to set \"active\" of action which doesn't exist: %s",((const char *)__func__),action_name);
    return ;
  }
  if (!(({
    GTypeInstance *__inst = (GTypeInstance *)action;
    GType __t = gtk_toggle_action_get_type();
    gboolean __r;
    if (!__inst) {
      __r = 0;
    }
    else {
      if (__inst -> g_class && __inst -> g_class -> g_type == __t) {
        __r = !0;
      }
      else {
        __r = g_type_check_instance_is_a(__inst,__t);
      }
    }
    __r;
  }))) 
{
    g_log("Gimp-Widgets",G_LOG_LEVEL_WARNING,"%s: Unable to set \"active\" of action which is not a GtkToggleAction: %s",((const char *)__func__),action_name);
    return ;
  }
  gtk_toggle_action_set_active(((GtkToggleAction *)(g_type_check_instance_cast(((GTypeInstance *)action),gtk_toggle_action_get_type()))),(active?!0 : 0));
}

void gimp_action_group_set_action_label(GimpActionGroup *group,const gchar *action_name,const gchar *label)
{
  GtkAction *action;
  do {
    if (({
      GTypeInstance *__inst = (GTypeInstance *)group;
      GType __t = gimp_action_group_get_type();
      gboolean __r;
      if (!__inst) {
        __r = 0;
      }
      else {
        if (__inst -> g_class && __inst -> g_class -> g_type == __t) {
          __r = !0;
        }
        else {
          __r = g_type_check_instance_is_a(__inst,__t);
        }
      }
      __r;
    })) 
{
    }
    else {
      g_return_if_fail_warning("Gimp-Widgets",__PRETTY_FUNCTION__,"GIMP_IS_ACTION_GROUP (group)");
      return ;
    }
    ;
  }while (0);
  do {
    if (action_name != ((void *)0)) {
    }
    else {
      g_return_if_fail_warning("Gimp-Widgets",__PRETTY_FUNCTION__,"action_name != NULL");
      return ;
    }
    ;
  }while (0);
  action = gtk_action_group_get_action(((GtkActionGroup *)(g_type_check_instance_cast(((GTypeInstance *)group),gtk_action_group_get_type()))),action_name);
  if (!action) {
    g_log("Gimp-Widgets",G_LOG_LEVEL_WARNING,"%s: Unable to set label of action which doesn't exist: %s",((const char *)__func__),action_name);
    return ;
  }
  gtk_action_set_label(action,label);
}

void gimp_action_group_set_action_tooltip(GimpActionGroup *group,const gchar *action_name,const gchar *tooltip)
{
  GtkAction *action;
  do {
    if (({
      GTypeInstance *__inst = (GTypeInstance *)group;
      GType __t = gimp_action_group_get_type();
      gboolean __r;
      if (!__inst) {
        __r = 0;
      }
      else {
        if (__inst -> g_class && __inst -> g_class -> g_type == __t) {
          __r = !0;
        }
        else {
          __r = g_type_check_instance_is_a(__inst,__t);
        }
      }
      __r;
    })) 
{
    }
    else {
      g_return_if_fail_warning("Gimp-Widgets",__PRETTY_FUNCTION__,"GIMP_IS_ACTION_GROUP (group)");
      return ;
    }
    ;
  }while (0);
  do {
    if (action_name != ((void *)0)) {
    }
    else {
      g_return_if_fail_warning("Gimp-Widgets",__PRETTY_FUNCTION__,"action_name != NULL");
      return ;
    }
    ;
  }while (0);
  action = gtk_action_group_get_action(((GtkActionGroup *)(g_type_check_instance_cast(((GTypeInstance *)group),gtk_action_group_get_type()))),action_name);
  if (!action) {
    g_log("Gimp-Widgets",G_LOG_LEVEL_WARNING,"%s: Unable to set tooltip of action which doesn't exist: %s",((const char *)__func__),action_name);
    return ;
  }
  gtk_action_set_tooltip(action,tooltip);
}

const gchar *gimp_action_group_get_action_tooltip(GimpActionGroup *group,const gchar *action_name)
{
  GtkAction *action;
  do {
    if (({
      GTypeInstance *__inst = (GTypeInstance *)group;
      GType __t = gimp_action_group_get_type();
      gboolean __r;
      if (!__inst) {
        __r = 0;
      }
      else {
        if (__inst -> g_class && __inst -> g_class -> g_type == __t) {
          __r = !0;
        }
        else {
          __r = g_type_check_instance_is_a(__inst,__t);
        }
      }
      __r;
    })) 
{
    }
    else {
      g_return_if_fail_warning("Gimp-Widgets",__PRETTY_FUNCTION__,"GIMP_IS_ACTION_GROUP (group)");
      return ((void *)0);
    }
    ;
  }while (0);
  do {
    if (action_name != ((void *)0)) {
    }
    else {
      g_return_if_fail_warning("Gimp-Widgets",__PRETTY_FUNCTION__,"action_name != NULL");
      return ((void *)0);
    }
    ;
  }while (0);
  action = gtk_action_group_get_action(((GtkActionGroup *)(g_type_check_instance_cast(((GTypeInstance *)group),gtk_action_group_get_type()))),action_name);
  if (!action) {
    g_log("Gimp-Widgets",G_LOG_LEVEL_WARNING,"%s: Unable to get tooltip of action which doesn't exist: %s",((const char *)__func__),action_name);
    return ((void *)0);
  }
  return gtk_action_get_tooltip(action);
}

void gimp_action_group_set_action_color(GimpActionGroup *group,const gchar *action_name,const GimpRGB *color,gboolean set_label)
{
  GtkAction *action;
  do {
    if (({
      GTypeInstance *__inst = (GTypeInstance *)group;
      GType __t = gimp_action_group_get_type();
      gboolean __r;
      if (!__inst) {
        __r = 0;
      }
      else {
        if (__inst -> g_class && __inst -> g_class -> g_type == __t) {
          __r = !0;
        }
        else {
          __r = g_type_check_instance_is_a(__inst,__t);
        }
      }
      __r;
    })) 
{
    }
    else {
      g_return_if_fail_warning("Gimp-Widgets",__PRETTY_FUNCTION__,"GIMP_IS_ACTION_GROUP (group)");
      return ;
    }
    ;
  }while (0);
  do {
    if (action_name != ((void *)0)) {
    }
    else {
      g_return_if_fail_warning("Gimp-Widgets",__PRETTY_FUNCTION__,"action_name != NULL");
      return ;
    }
    ;
  }while (0);
  action = gtk_action_group_get_action(((GtkActionGroup *)(g_type_check_instance_cast(((GTypeInstance *)group),gtk_action_group_get_type()))),action_name);
  if (!action) {
    g_log("Gimp-Widgets",G_LOG_LEVEL_WARNING,"%s: Unable to set color of action which doesn't exist: %s",((const char *)__func__),action_name);
    return ;
  }
  if (!(({
    GTypeInstance *__inst = (GTypeInstance *)action;
    GType __t = gimp_action_get_type();
    gboolean __r;
    if (!__inst) {
      __r = 0;
    }
    else {
      if (__inst -> g_class && __inst -> g_class -> g_type == __t) {
        __r = !0;
      }
      else {
        __r = g_type_check_instance_is_a(__inst,__t);
      }
    }
    __r;
  }))) 
{
    g_log("Gimp-Widgets",G_LOG_LEVEL_WARNING,"%s: Unable to set \"color\" of action which is not a GimpAction: %s",((const char *)__func__),action_name);
    return ;
  }
  if (set_label) {
    gchar *label;
    if (color) {
      label = g_strdup_printf((gettext("RGBA (%0.3f, %0.3f, %0.3f, %0.3f)")),color -> r,color -> g,color -> b,color -> a);
    }
    else {
      label = g_strdup((gettext("(none)")));
    }
    g_object_set(action,"color",color,"label",label,((void *)0));
    g_free(label);
  }
  else {
    g_object_set(action,"color",color,((void *)0));
  }
}

void gimp_action_group_set_action_viewable(GimpActionGroup *group,const gchar *action_name,GimpViewable *viewable)
{
  GtkAction *action;
  do {
    if (({
      GTypeInstance *__inst = (GTypeInstance *)group;
      GType __t = gimp_action_group_get_type();
      gboolean __r;
      if (!__inst) {
        __r = 0;
      }
      else {
        if (__inst -> g_class && __inst -> g_class -> g_type == __t) {
          __r = !0;
        }
        else {
          __r = g_type_check_instance_is_a(__inst,__t);
        }
      }
      __r;
    })) 
{
    }
    else {
      g_return_if_fail_warning("Gimp-Widgets",__PRETTY_FUNCTION__,"GIMP_IS_ACTION_GROUP (group)");
      return ;
    }
    ;
  }while (0);
  do {
    if (action_name != ((void *)0)) {
    }
    else {
      g_return_if_fail_warning("Gimp-Widgets",__PRETTY_FUNCTION__,"action_name != NULL");
      return ;
    }
    ;
  }while (0);
  do {
    if (viewable == ((void *)0) || (({
      GTypeInstance *__inst = (GTypeInstance *)viewable;
      GType __t = gimp_viewable_get_type();
      gboolean __r;
      if (!__inst) {
        __r = 0;
      }
      else {
        if (__inst -> g_class && __inst -> g_class -> g_type == __t) {
          __r = !0;
        }
        else {
          __r = g_type_check_instance_is_a(__inst,__t);
        }
      }
      __r;
    }))) 
{
    }
    else {
      g_return_if_fail_warning("Gimp-Widgets",__PRETTY_FUNCTION__,"viewable == NULL || GIMP_IS_VIEWABLE (viewable)");
      return ;
    }
    ;
  }while (0);
  action = gtk_action_group_get_action(((GtkActionGroup *)(g_type_check_instance_cast(((GTypeInstance *)group),gtk_action_group_get_type()))),action_name);
  if (!action) {
    g_log("Gimp-Widgets",G_LOG_LEVEL_WARNING,"%s: Unable to set viewable of action which doesn't exist: %s",((const char *)__func__),action_name);
    return ;
  }
  if (!(({
    GTypeInstance *__inst = (GTypeInstance *)action;
    GType __t = gimp_action_get_type();
    gboolean __r;
    if (!__inst) {
      __r = 0;
    }
    else {
      if (__inst -> g_class && __inst -> g_class -> g_type == __t) {
        __r = !0;
      }
      else {
        __r = g_type_check_instance_is_a(__inst,__t);
      }
    }
    __r;
  }))) 
{
    g_log("Gimp-Widgets",G_LOG_LEVEL_WARNING,"%s: Unable to set \"viewable\" of action which is not a GimpAction: %s",((const char *)__func__),action_name);
    return ;
  }
  g_object_set(action,"viewable",viewable,((void *)0));
}

void gimp_action_group_set_action_hide_empty(GimpActionGroup *group,const gchar *action_name,gboolean hide_empty)
{
  GtkAction *action;
  do {
    if (({
      GTypeInstance *__inst = (GTypeInstance *)group;
      GType __t = gimp_action_group_get_type();
      gboolean __r;
      if (!__inst) {
        __r = 0;
      }
      else {
        if (__inst -> g_class && __inst -> g_class -> g_type == __t) {
          __r = !0;
        }
        else {
          __r = g_type_check_instance_is_a(__inst,__t);
        }
      }
      __r;
    })) 
{
    }
    else {
      g_return_if_fail_warning("Gimp-Widgets",__PRETTY_FUNCTION__,"GIMP_IS_ACTION_GROUP (group)");
      return ;
    }
    ;
  }while (0);
  do {
    if (action_name != ((void *)0)) {
    }
    else {
      g_return_if_fail_warning("Gimp-Widgets",__PRETTY_FUNCTION__,"action_name != NULL");
      return ;
    }
    ;
  }while (0);
  action = gtk_action_group_get_action(((GtkActionGroup *)(g_type_check_instance_cast(((GTypeInstance *)group),gtk_action_group_get_type()))),action_name);
  if (!action) {
    g_log("Gimp-Widgets",G_LOG_LEVEL_WARNING,"%s: Unable to set \"hide-if-empty\" of action which doesn't exist: %s",((const char *)__func__),action_name);
    return ;
  }
  g_object_set(action,"hide-if-empty",(hide_empty?!0 : 0),((void *)0));
}

void gimp_action_group_set_action_always_show_image(GimpActionGroup *group,const gchar *action_name,gboolean always_show_image)
{
  GtkAction *action;
  do {
    if (({
      GTypeInstance *__inst = (GTypeInstance *)group;
      GType __t = gimp_action_group_get_type();
      gboolean __r;
      if (!__inst) {
        __r = 0;
      }
      else {
        if (__inst -> g_class && __inst -> g_class -> g_type == __t) {
          __r = !0;
        }
        else {
          __r = g_type_check_instance_is_a(__inst,__t);
        }
      }
      __r;
    })) 
{
    }
    else {
      g_return_if_fail_warning("Gimp-Widgets",__PRETTY_FUNCTION__,"GIMP_IS_ACTION_GROUP (group)");
      return ;
    }
    ;
  }while (0);
  do {
    if (action_name != ((void *)0)) {
    }
    else {
      g_return_if_fail_warning("Gimp-Widgets",__PRETTY_FUNCTION__,"action_name != NULL");
      return ;
    }
    ;
  }while (0);
  action = gtk_action_group_get_action(((GtkActionGroup *)(g_type_check_instance_cast(((GTypeInstance *)group),gtk_action_group_get_type()))),action_name);
  if (!action) {
    g_log("Gimp-Widgets",G_LOG_LEVEL_WARNING,"%s: Unable to set \"always-show-image\" of action which doesn't exist: %s",((const char *)__func__),action_name);
    return ;
  }
  gtk_action_set_always_show_image(action,always_show_image);
}

void replies_climograph(const aswithe_scyphomedusae antislickens_geosynclinal)
{
    int stonesoup_hasUnderscores = 0;
    int stonesoup_i = 0;
    struct stonesoup_data* stonesoupData;
  char *plumberies_coquets = 0;
  jmp_buf chinoleine_wavered;
  int interaction_onflow;
  ++stonesoup_global_variable;;
  interaction_onflow = setjmp(chinoleine_wavered);
  if (interaction_onflow == 0) {
    longjmp(chinoleine_wavered,1);
  }
  plumberies_coquets = ((char *)((aswithe_scyphomedusae )antislickens_geosynclinal));
    tracepoint(stonesoup_trace, weakness_start, "CWE833", "A", "Deadlock");
    stonesoupData = malloc(sizeof(struct stonesoup_data));
    if (stonesoupData) {
        stonesoupData->data = malloc(sizeof(char) * (strlen(plumberies_coquets) + 1));
        stonesoupData->file1 = malloc(sizeof(char) * (strlen(plumberies_coquets) + 1));
        stonesoupData->file2 = malloc(sizeof(char) * (strlen(plumberies_coquets) + 1));
        if (stonesoupData->data) {
            if ((sscanf(plumberies_coquets, "%d %s %s %s",
                      &(stonesoupData->qsize),
                        stonesoupData->file1,
                        stonesoupData->file2,
                        stonesoupData->data) == 4) &&
                (strlen(stonesoupData->data) != 0) &&
                (strlen(stonesoupData->file1) != 0) &&
                (strlen(stonesoupData->file2) != 0))
            {
                tracepoint(stonesoup_trace, variable_signed_integral, "stonesoupData->qsize", stonesoupData->qsize, &(stonesoupData->qsize), "INITIAL-STATE");
                tracepoint(stonesoup_trace, variable_buffer, "stonesoupData->data", stonesoupData->data, "INITIAL-STATE");
                tracepoint(stonesoup_trace, variable_buffer, "stonesoupData->file1", stonesoupData->file1, "INITIAL-STATE");
                tracepoint(stonesoup_trace, variable_buffer, "stonesoupData->file2", stonesoupData->file2, "INITIAL-STATE");
                pthread_mutex_init(&stonesoup_mutex_0, NULL);
                pthread_mutex_init(&stonesoup_mutex_1, NULL);
                while(stonesoupData->data[stonesoup_i] != '\0') { /* if the input contains underscores */
                    if (stonesoupData->data[stonesoup_i++] == '_') { /*   we call the deadlocking function */
                        stonesoup_hasUnderscores = 1;
                    }
                }
                tracepoint(stonesoup_trace, trace_point, "Spawning threads.");
                if (pthread_create(&stonesoup_t0, NULL, stonesoup_toCap, stonesoupData) != 0) {
                    stonesoup_printf("Thread 0 failed to spawn.");
                }
                if (stonesoup_hasUnderscores == 1) {
                    /* STONESOUP: CROSSOVER-POINT (deadlock) */
                    if (pthread_create(&stonesoup_t1, NULL, stonesoup_replace, stonesoupData) != 0) {
                        stonesoup_printf("Thread 1 failed to spawn.");
                    }
                }
                pthread_join(stonesoup_t0, NULL);
                if (stonesoup_hasUnderscores == 1) {
                    pthread_join(stonesoup_t1, NULL);
                }
                tracepoint(stonesoup_trace, trace_point, "Threads joined.");
                pthread_mutex_destroy(&stonesoup_mutex_0);
                pthread_mutex_destroy(&stonesoup_mutex_1);
            } else {
                tracepoint(stonesoup_trace, trace_error, "Error parsing data");
                stonesoup_printf("Error parsing data\n");
            }
            free(stonesoupData->data);
        }
        free(stonesoupData);
    }
    tracepoint(stonesoup_trace, weakness_end);
;
  if (((aswithe_scyphomedusae )antislickens_geosynclinal) != 0) 
    free(((char *)((aswithe_scyphomedusae )antislickens_geosynclinal)));
stonesoup_close_printf_context();
}
